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
import org.calyxos.seedvault.cli.restore.AppBackupRestorer

/**
 * `decrypt-app` – decrypts one or all app data tars from an app backup snapshot.
 *
 * Usage:
 * ```
 * seedvault-cli decrypt-app \
 *   --snapshot <64-char-hash> \
 *   --output-dir /path/to/output \
 *   /path/to/.SeedVaultAndroidBackup
 * ```
 *
 * Each app's data is written as a tar stream to `<output-dir>/<packageName>.tar`.
 */
internal class DecryptAppCommand : CliktCommand(
    name = "decrypt-app",
    help = "Decrypt an app backup snapshot and extract app data tar files.",
) {

    private val backupDir by argument(
        name = "BACKUP_DIR",
        help = "Path to the Seedvault backup root directory (usually .SeedVaultAndroidBackup).",
    ).path(mustExist = true, canBeFile = false, canBeDir = true)

    private val snapshotHash by option(
        "--snapshot", "-s",
        help = "64-char hex hash of the snapshot to decrypt. " +
            "Use 'list' to discover available hashes.",
    ).required()

    private val outputDir by option(
        "--output-dir", "-o",
        help = "Directory where decrypted app tars will be written.",
    ).path(canBeFile = false, canBeDir = true).required()

    private val packageName by option(
        "--package", "-p",
        help = "Restore only this package name (e.g. com.example.app). " +
            "If omitted, all apps in the snapshot are restored.",
    )

    private val mnemonicOpt by option(
        "--mnemonic", "-m",
        help = "12-word BIP39 recovery phrase. If not provided, will be prompted interactively.",
        envvar = "SEEDVAULT_MNEMONIC",
    )

    override fun run() {
        val mnemonic = mnemonicOpt ?: promptMnemonic()
        val keyManager = try {
            MnemonicKeyDeriver.deriveFromMnemonic(mnemonic)
        } catch (e: Exception) {
            echo("Error: invalid mnemonic – ${e.message}", err = true)
            return
        }

        val backupRootFile = backupDir.toFile()
        val restorer = AppBackupRestorer(backupRootFile, keyManager)

        // Find the snapshot across all repository folders
        val snapshotInfo = restorer.findRepoDirs().flatMap { repoDir ->
            restorer.listSnapshotsInRepo(repoDir)
        }.find { it.hash == snapshotHash }

        if (snapshotInfo == null) {
            echo(
                "Error: snapshot '$snapshotHash' not found. " +
                    "Use 'list' to see available snapshots.",
                err = true,
            )
            return
        }

        val outFile = outputDir.toFile()
        var restored = 0
        var failed = 0

        echo("Restoring from snapshot ${snapshotInfo.hash} …")
        restorer.restoreApps(
            snapshotInfo = snapshotInfo,
            outputDir = outFile,
            packageFilter = packageName,
        ) { pkg, success ->
            if (success) {
                echo("  ✓  $pkg")
                restored++
            } else {
                echo("  ✗  $pkg (failed)", err = true)
                failed++
            }
        }

        echo("\nDone: $restored restored, $failed failed.")
    }
}
