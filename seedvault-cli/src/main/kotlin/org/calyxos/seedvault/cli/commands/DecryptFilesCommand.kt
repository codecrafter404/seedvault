/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.commands

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.path
import org.calyxos.seedvault.cli.crypto.MnemonicKeyDeriver
import org.calyxos.seedvault.cli.restore.FileBackupRestorer

/**
 * `decrypt-files` – decrypts a file/media backup snapshot and extracts the original files.
 *
 * Usage:
 * ```
 * seedvault-cli decrypt-files \
 *   --snapshot <13-digit-timestamp> \
 *   --output-dir /path/to/output \
 *   /path/to/.SeedVaultAndroidBackup
 * ```
 */
internal class DecryptFilesCommand : CliktCommand(
    name = "decrypt-files",
    help = "Decrypt a file/media backup snapshot and restore the original files.",
) {

    private val backupDir by argument(
        name = "BACKUP_DIR",
        help = "Path to the Seedvault backup root directory (usually .SeedVaultAndroidBackup).",
    ).path(mustExist = true, canBeFile = false, canBeDir = true)

    private val snapshotTimestamp by option(
        "--snapshot", "-s",
        help = "Epoch-millisecond timestamp of the snapshot to decrypt. " +
            "Use 'list' to discover available snapshots.",
    ).required()

    private val outputDir by option(
        "--output-dir", "-o",
        help = "Directory where decrypted files will be written, preserving relative paths.",
    ).path(canBeFile = false, canBeDir = true).required()

    private val mnemonicOpt by option(
        "--mnemonic", "-m",
        help = "12-word BIP39 recovery phrase. If not provided, will be prompted interactively.",
        envvar = "SEEDVAULT_MNEMONIC",
    )

    override fun run() {
        val timestamp = snapshotTimestamp.toLongOrNull()
        if (timestamp == null) {
            echo("Error: --snapshot must be a 13-digit epoch-millisecond timestamp.", err = true)
            return
        }

        val mnemonic = mnemonicOpt ?: promptMnemonic()
        val keyManager = try {
            MnemonicKeyDeriver.deriveFromMnemonic(mnemonic)
        } catch (e: Exception) {
            echo("Error: invalid mnemonic – ${e.message}", err = true)
            return
        }

        val backupRootFile = backupDir.toFile()
        val restorer = FileBackupRestorer(backupRootFile, keyManager)

        // Find the snapshot across all .sv folders
        val snapshotInfo = restorer.findFileFolders().flatMap { svDir ->
            restorer.listSnapshotsInFolder(svDir)
        }.find { it.timestamp == timestamp }

        if (snapshotInfo == null) {
            echo(
                "Error: snapshot '$timestamp' not found. " +
                    "Use 'list' to see available snapshots.",
                err = true,
            )
            return
        }

        val outFile = outputDir.toFile()
        var restored = 0
        var failed = 0

        echo("Restoring file snapshot $timestamp …")
        restorer.restoreFiles(snapshotInfo, outFile) { relPath, success ->
            if (success) {
                echo("  ✓  $relPath")
                restored++
            } else {
                echo("  ✗  $relPath (failed)", err = true)
                failed++
            }
        }

        echo("\nDone: $restored restored, $failed failed.")
    }
}
