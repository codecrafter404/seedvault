/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.restore

import com.stevesoltys.seedvault.proto.Snapshot
import org.calyxos.seedvault.cli.crypto.JvmKeyManager
import org.calyxos.seedvault.cli.restore.BackupDecryptor.sha256
import org.calyxos.seedvault.cli.restore.BackupDecryptor.toHexString
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.SequenceInputStream
import java.security.GeneralSecurityException
import java.util.Enumeration
import java.util.regex.Pattern

/**
 * Repository folder name: 64 lower-case hex characters.
 * Matches [org.calyxos.seedvault.core.backends.Constants.repoIdRegex].
 */
private val REPO_ID_PATTERN: Pattern = Pattern.compile("^[a-f0-9]{64}$")

/**
 * Snapshot file name: <64-char-hex>.snapshot
 * Matches [org.calyxos.seedvault.core.backends.Constants.appSnapshotRegex].
 */
private val SNAPSHOT_PATTERN: Pattern = Pattern.compile("^([a-f0-9]{64})\\.snapshot$")

/**
 * Blob folder name: 2 lower-case hex characters.
 * Matches [org.calyxos.seedvault.core.backends.Constants.blobFolderRegex].
 */
private val BLOB_FOLDER_PATTERN: Pattern = Pattern.compile("^[a-f0-9]{2}$")

/**
 * Decrypts and restores Seedvault **app** backups (format version 2).
 *
 * Repository layout on disk (relative to the backup root):
 * ```
 * <backupRoot>/
 * └── <repoId 64-hex>/
 *     ├── <hash>.snapshot      ← encrypted protobuf Snapshot
 *     └── <2-hex>/
 *         └── <64-hex>         ← encrypted+compressed blob
 * ```
 */
internal class AppBackupRestorer(
    private val backupRoot: File,
    private val keyManager: JvmKeyManager,
) {

    private val streamKey: ByteArray by lazy { keyManager.appStreamKey() }

    // -------------------------------------------------------------------------
    // Discovery
    // -------------------------------------------------------------------------

    /**
     * Returns all [SnapshotInfo] objects found in the backup root, across all repositories.
     * Snapshots that cannot be decrypted are silently skipped.
     */
    internal fun listSnapshots(): List<SnapshotInfo> {
        val result = mutableListOf<SnapshotInfo>()
        for (repoDir in findRepoDirs()) {
            result += listSnapshotsInRepo(repoDir)
        }
        return result.sortedByDescending { it.snapshot.token }
    }

    /**
     * Lists snapshots available inside a single [repoDir].
     * Snapshots that cannot be decrypted are silently skipped.
     */
    internal fun listSnapshotsInRepo(repoDir: File): List<SnapshotInfo> {
        val result = mutableListOf<SnapshotInfo>()
        val files = repoDir.listFiles() ?: return result
        for (file in files) {
            val matcher = SNAPSHOT_PATTERN.matcher(file.name)
            if (!matcher.matches()) continue
            val hash = matcher.group(1)!!
            try {
                val snapshot = loadSnapshot(file, hash)
                result += SnapshotInfo(repoDir.name, hash, snapshot)
            } catch (e: Exception) {
                System.err.println("Warning: could not decrypt snapshot ${file.name}: ${e.message}")
            }
        }
        return result
    }

    /** Returns all repository directories (64-char hex folders) inside [backupRoot]. */
    internal fun findRepoDirs(): List<File> {
        return (backupRoot.listFiles() ?: emptyArray<File>())
            .filter { it.isDirectory && REPO_ID_PATTERN.matcher(it.name).matches() }
    }

    // -------------------------------------------------------------------------
    // Snapshot loading
    // -------------------------------------------------------------------------

    /**
     * Loads and decrypts a single snapshot file, verifying its SHA-256 hash.
     *
     * @param file  the `.snapshot` file on disk
     * @param expectedHash  the SHA-256 hash encoded in the file name (without extension)
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    internal fun loadSnapshot(file: File, expectedHash: String): Snapshot {
        val cipherText = file.readBytes()
        verifySha256(cipherText, expectedHash)
        val inputStream = cipherText.inputStream()
        return BackupDecryptor.decryptAndDecompressAppBlob(inputStream, streamKey).use { stream ->
            Snapshot.parseFrom(stream)
        }
    }

    // -------------------------------------------------------------------------
    // Blob / chunk loading
    // -------------------------------------------------------------------------

    /**
     * Returns a concatenated, decrypted and decompressed [InputStream] for the given app.
     *
     * The caller is responsible for closing the returned stream.
     *
     * @param snapshot  the [Snapshot] containing blob metadata
     * @param repoId    the repository folder name
     * @param app       the [Snapshot.App] whose data should be restored
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    internal fun openAppDataStream(
        snapshot: Snapshot,
        repoId: String,
        app: Snapshot.App,
    ): InputStream {
        val blobMap = snapshot.blobsMap
        val repoDir = File(backupRoot, repoId)

        // Build ordered list of chunk streams (each decompressed independently)
        val streams: List<InputStream> = app.chunkIdsList.map { chunkId ->
            val chunkIdHex = chunkId.toByteArray()
                .joinToString("") { "%02x".format(it) }
            val blob = blobMap[chunkIdHex]
                ?: throw IOException("Blob not found for chunk $chunkIdHex")
            val storageId = blob.id.toByteArray().joinToString("") { "%02x".format(it) }
            loadBlob(repoDir, storageId)
        }

        if (streams.isEmpty()) return InputStream.nullInputStream()

        // Concatenate into one sequential stream
        val enumeration = object : Enumeration<InputStream> {
            private val iter = streams.iterator()
            override fun hasMoreElements() = iter.hasNext()
            override fun nextElement() = iter.next()
        }
        return SequenceInputStream(enumeration)
    }

    /**
     * Loads, verifies, decrypts and decompresses a single blob by its [storageId].
     *
     * @param repoDir   the repository directory containing the blob subdirectories
     * @param storageId the 64-char hex storage ID (equals SHA-256 of the ciphertext)
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    internal fun loadBlob(repoDir: File, storageId: String): InputStream {
        val blobFile = File(repoDir, "${storageId.substring(0, 2)}/$storageId")
        if (!blobFile.isFile) throw IOException("Blob file not found: $blobFile")
        val cipherText = blobFile.readBytes()
        verifySha256(cipherText, storageId)
        return BackupDecryptor.decryptAndDecompressAppBlob(cipherText.inputStream(), streamKey)
    }

    // -------------------------------------------------------------------------
    // Restore
    // -------------------------------------------------------------------------

    /**
     * Restores all apps from [snapshotInfo] to [outputDir].
     *
     * Each app's decrypted tar stream is written to `<outputDir>/<packageName>.tar`.
     * If [packageFilter] is non-null only that package is restored.
     *
     * @param snapshotInfo  the snapshot to restore from
     * @param outputDir     destination directory (created if it does not exist)
     * @param packageFilter optional package name to restore a single app
     * @param onProgress    called after each app is written; receives (packageName, success)
     */
    @Throws(IOException::class)
    internal fun restoreApps(
        snapshotInfo: SnapshotInfo,
        outputDir: File,
        packageFilter: String? = null,
        onProgress: (packageName: String, success: Boolean) -> Unit = { _, _ -> },
    ) {
        outputDir.mkdirs()
        val snapshot = snapshotInfo.snapshot
        val appsToRestore = if (packageFilter != null) {
            val app = snapshot.appsMap[packageFilter]
                ?: throw IOException("Package '$packageFilter' not found in snapshot")
            mapOf(packageFilter to app)
        } else {
            snapshot.appsMap
        }

        for ((packageName, app) in appsToRestore) {
            val outFile = File(outputDir, "$packageName.tar")
            try {
                openAppDataStream(snapshot, snapshotInfo.repoId, app).use { stream ->
                    outFile.outputStream().use { out -> stream.copyTo(out) }
                }
                onProgress(packageName, true)
            } catch (e: Exception) {
                System.err.println("Warning: failed to restore $packageName: ${e.message}")
                onProgress(packageName, false)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private fun verifySha256(bytes: ByteArray, expectedHex: String) {
        val actual = sha256(bytes).toHexString()
        if (actual != expectedHex) {
            throw IOException("SHA-256 mismatch for file: expected $expectedHex, got $actual")
        }
    }
}

/** Metadata about a discovered snapshot. */
internal data class SnapshotInfo(
    /** The 64-char hex repository ID (the folder name). */
    val repoId: String,
    /** The 64-char hex SHA-256 hash of the snapshot ciphertext (the file name without extension). */
    val hash: String,
    /** The decrypted and parsed snapshot protobuf. */
    val snapshot: Snapshot,
)
