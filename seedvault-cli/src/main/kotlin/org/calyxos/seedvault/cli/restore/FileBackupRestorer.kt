/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.restore

import org.calyxos.backup.storage.backup.BackupSnapshot
import org.calyxos.seedvault.cli.crypto.JvmKeyManager
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.util.regex.Pattern
import java.util.zip.ZipInputStream

/**
 * File backup folder name: 16 lower-case hex chars + ".sv" extension.
 * Matches [org.calyxos.seedvault.core.backends.Constants.fileFolderRegex].
 */
private val FILE_FOLDER_PATTERN: Pattern = Pattern.compile("^[a-f0-9]{16}\\.sv$")

/**
 * Snapshot file name: <13-digit timestamp>.SeedSnap
 * Matches [org.calyxos.seedvault.core.backends.Constants.fileSnapshotRegex].
 */
private val FILE_SNAPSHOT_PATTERN: Pattern = Pattern.compile("^([0-9]{13})\\.SeedSnap$")

// Matches StreamCrypto constants
private const val TYPE_CHUNK: Byte = 0x00
private const val TYPE_SNAPSHOT: Byte = 0x01
private const val KEY_SIZE_BYTES = 32

/**
 * Decrypts and restores Seedvault **file/media** backups (storage module, format version 0).
 *
 * Repository layout on disk (relative to the backup root):
 * ```
 * <backupRoot>/
 * └── <androidId>.sv/
 *     ├── <timestamp>.SeedSnap   ← encrypted protobuf BackupSnapshot
 *     └── <2-hex>/
 *         └── <64-hex>           ← encrypted file chunk
 * ```
 */
internal class FileBackupRestorer(
    private val backupRoot: File,
    private val keyManager: JvmKeyManager,
) {

    private val streamKey: ByteArray by lazy { keyManager.fileStreamKey() }

    // -------------------------------------------------------------------------
    // Discovery
    // -------------------------------------------------------------------------

    /**
     * Returns all [FileSnapshotInfo] objects found in the backup root.
     * Snapshots that cannot be decrypted are silently skipped.
     */
    internal fun listSnapshots(): List<FileSnapshotInfo> {
        val result = mutableListOf<FileSnapshotInfo>()
        for (svDir in findFileFolders()) {
            result += listSnapshotsInFolder(svDir)
        }
        return result.sortedByDescending { it.timestamp }
    }

    /** Returns all `.sv` directories inside [backupRoot]. */
    internal fun findFileFolders(): List<File> {
        return (backupRoot.listFiles() ?: emptyArray<File>())
            .filter { it.isDirectory && FILE_FOLDER_PATTERN.matcher(it.name).matches() }
    }

    /** Lists snapshots in a single `.sv` directory. Failures are silently skipped. */
    internal fun listSnapshotsInFolder(svDir: File): List<FileSnapshotInfo> {
        val result = mutableListOf<FileSnapshotInfo>()
        val files = svDir.listFiles() ?: return result
        for (file in files) {
            val matcher = FILE_SNAPSHOT_PATTERN.matcher(file.name)
            if (!matcher.matches()) continue
            val timestamp = matcher.group(1)!!.toLong()
            try {
                val snapshot = loadSnapshot(file, timestamp)
                result += FileSnapshotInfo(svDir.name, timestamp, snapshot)
            } catch (e: Exception) {
                System.err.println(
                    "Warning: could not decrypt file snapshot ${file.name}: ${e.message}"
                )
            }
        }
        return result
    }

    // -------------------------------------------------------------------------
    // Snapshot loading
    // -------------------------------------------------------------------------

    /**
     * Loads, decrypts and parses a `.SeedSnap` file.
     *
     * @param file       the `.SeedSnap` file on disk
     * @param timestamp  the epoch-millisecond timestamp encoded in the file name
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    internal fun loadSnapshot(file: File, timestamp: Long): BackupSnapshot {
        val aad = getAssociatedDataForSnapshot(timestamp, 0.toByte())
        return file.inputStream().use { raw ->
            BackupDecryptor.decryptFileStream(raw, streamKey, aad).use { plain ->
                BackupSnapshot.parseFrom(plain)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Restore
    // -------------------------------------------------------------------------

    /**
     * Restores all files from [snapshotInfo] to [outputDir].
     *
     * Files are written to `<outputDir>/<volume>/<path>/<name>` preserving the original structure.
     *
     * @param snapshotInfo  the snapshot to restore from
     * @param outputDir     destination directory (created if it does not exist)
     * @param onProgress    called after each file is written; receives (relPath, success)
     */
    @Throws(IOException::class)
    internal fun restoreFiles(
        snapshotInfo: FileSnapshotInfo,
        outputDir: File,
        onProgress: (relPath: String, success: Boolean) -> Unit = { _, _ -> },
    ) {
        outputDir.mkdirs()
        val snapshot = snapshotInfo.snapshot
        val svDir = File(backupRoot, snapshotInfo.userId)

        for (mediaFile in snapshot.mediaFilesList) {
            val relPath = buildRelPath(mediaFile.volume, mediaFile.path, mediaFile.name)
            restoreFileChunks(
                svDir = svDir,
                chunkIds = mediaFile.chunkIdsList,
                zipIndex = mediaFile.zipIndex,
                outputFile = File(outputDir, relPath),
                version = 0,
                onProgress = { success -> onProgress(relPath, success) },
            )
        }

        for (docFile in snapshot.documentFilesList) {
            val relPath = buildRelPath(docFile.volume, docFile.path, docFile.name)
            restoreFileChunks(
                svDir = svDir,
                chunkIds = docFile.chunkIdsList,
                zipIndex = docFile.zipIndex,
                outputFile = File(outputDir, relPath),
                version = 0,
                onProgress = { success -> onProgress(relPath, success) },
            )
        }
    }

    private fun restoreFileChunks(
        svDir: File,
        chunkIds: List<String>,
        zipIndex: Int,
        outputFile: File,
        version: Int,
        onProgress: (success: Boolean) -> Unit,
    ) {
        try {
            outputFile.parentFile?.mkdirs()
            if (chunkIds.size == 1 && zipIndex != 0) {
                // Zip chunk: the file is stored inside a ZIP together with other small files
                restoreFromZipChunk(svDir, chunkIds[0], zipIndex, outputFile, version)
            } else {
                // Single chunk or multi-chunk: concatenate plaintext from all chunks
                restoreFromChunks(svDir, chunkIds, outputFile, version)
            }
            onProgress(true)
        } catch (e: Exception) {
            System.err.println("Warning: failed to restore ${outputFile.name}: ${e.message}")
            onProgress(false)
        }
    }

    private fun restoreFromChunks(
        svDir: File,
        chunkIds: List<String>,
        outputFile: File,
        version: Int,
    ) {
        outputFile.outputStream().use { out ->
            for (chunkId in chunkIds) {
                openChunk(svDir, chunkId, version).use { stream -> stream.copyTo(out) }
            }
        }
    }

    private fun restoreFromZipChunk(
        svDir: File,
        chunkId: String,
        zipIndex: Int,
        outputFile: File,
        version: Int,
    ) {
        val indexName = zipIndex.toString()
        openChunk(svDir, chunkId, version).use { chunkStream ->
            ZipInputStream(chunkStream).use { zip ->
                var found = false
                var entry = zip.nextEntry
                while (entry != null) {
                    if (entry.name == indexName) {
                        outputFile.outputStream().use { out -> zip.copyTo(out) }
                        found = true
                        break
                    }
                    zip.closeEntry()
                    entry = zip.nextEntry
                }
                if (!found) throw IOException(
                    "Zip entry '$indexName' not found in chunk $chunkId"
                )
            }
        }
    }

    /**
     * Opens a decrypted chunk stream.
     *
     * @param svDir   the `.sv` directory containing the chunk subdirectories
     * @param chunkId the 64-char hex chunk ID (also used to compute the AAD)
     * @param version the backup version byte (0 for file backups)
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    internal fun openChunk(svDir: File, chunkId: String, version: Int): InputStream {
        val chunkFile = File(svDir, "${chunkId.substring(0, 2)}/$chunkId")
        if (!chunkFile.isFile) throw IOException("Chunk file not found: $chunkFile")
        val aad = getAssociatedDataForChunk(chunkId, version.toByte())
        return BackupDecryptor.decryptFileStream(chunkFile.inputStream(), streamKey, aad)
    }

    // -------------------------------------------------------------------------
    // AAD helpers (mirrors StreamCrypto)
    // -------------------------------------------------------------------------

    private fun getAssociatedDataForChunk(chunkId: String, version: Byte): ByteArray {
        val chunkIdBytes = chunkId.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        check(chunkIdBytes.size == KEY_SIZE_BYTES) {
            "Expected $KEY_SIZE_BYTES bytes for chunk ID, got ${chunkIdBytes.size}"
        }
        return ByteBuffer.allocate(2 + KEY_SIZE_BYTES)
            .put(version)
            .put(TYPE_CHUNK)
            .put(chunkIdBytes)
            .array()
    }

    private fun getAssociatedDataForSnapshot(timestamp: Long, version: Byte): ByteArray {
        val timestampBytes = ByteArray(8).apply {
            var t = timestamp
            for (i in 7 downTo 0) {
                this[i] = (t and 0xFF).toByte()
                t = t shr 8
            }
        }
        return ByteBuffer.allocate(2 + 8)
            .put(version)
            .put(TYPE_SNAPSHOT)
            .put(timestampBytes)
            .array()
    }

    private fun buildRelPath(volume: String, path: String, name: String): String {
        val prefix = if (volume.isNotEmpty()) volume else "primary"
        val dir = path.trimEnd('/')
        return if (dir.isEmpty()) "$prefix/$name" else "$prefix/$dir/$name"
    }
}

/** Metadata about a discovered file-backup snapshot. */
internal data class FileSnapshotInfo(
    /** The `.sv` folder name (e.g. `bbcc5909347d0b83.sv`). */
    val userId: String,
    /** Epoch-millisecond timestamp encoded in the file name. */
    val timestamp: Long,
    /** The decrypted and parsed snapshot protobuf. */
    val snapshot: BackupSnapshot,
)
