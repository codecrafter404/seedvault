/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.commands

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import org.calyxos.seedvault.cli.crypto.MnemonicKeyDeriver
import org.calyxos.seedvault.cli.restore.AppBackupRestorer
import org.calyxos.seedvault.cli.restore.FileBackupRestorer
import org.calyxos.seedvault.cli.restore.SnapshotInfo
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val DATE_FMT: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault())

/**
 * `list` – prints all available snapshots found in [backupDir].
 *
 * Usage:
 * ```
 * seedvault-cli --backup-dir /path/to/.SeedVaultAndroidBackup list
 * ```
 */
internal class ListCommand : CliktCommand(
    name = "list",
    help = "List all available snapshots in the backup directory.",
) {

    private val backupDir by argument(
        name = "BACKUP_DIR",
        help = "Path to the Seedvault backup root directory (usually .SeedVaultAndroidBackup).",
    ).path(mustExist = true, canBeFile = false, canBeDir = true)

    private val mnemonicOpt by option(
        "--mnemonic", "-m",
        help = "12-word BIP39 recovery phrase. If not provided, will be prompted interactively.",
        envvar = "SEEDVAULT_MNEMONIC",
    )

    private val quiet by option("--quiet", "-q", help = "Only print snapshot hashes.").flag()

    override fun run() {
        val mnemonic = mnemonicOpt ?: promptMnemonic()
        val keyManager = try {
            MnemonicKeyDeriver.deriveFromMnemonic(mnemonic)
        } catch (e: Exception) {
            echo("Error: invalid mnemonic – ${e.message}", err = true)
            return
        }

        val backupRootFile = backupDir.toFile()
        val appRestorer = AppBackupRestorer(backupRootFile, keyManager)
        val fileRestorer = FileBackupRestorer(backupRootFile, keyManager)

        val appSnapshots = appRestorer.listSnapshots()
        val fileSnapshots = fileRestorer.listSnapshots()

        if (appSnapshots.isEmpty() && fileSnapshots.isEmpty()) {
            echo("No snapshots found in: $backupRootFile")
            return
        }

        if (appSnapshots.isNotEmpty()) {
            if (!quiet) echo("\n=== App Backup Snapshots ===")
            for (info in appSnapshots) {
                if (quiet) {
                    echo(info.hash)
                } else {
                    printAppSnapshot(info)
                }
            }
        }

        if (fileSnapshots.isNotEmpty()) {
            if (!quiet) echo("\n=== File/Media Backup Snapshots ===")
            for (info in fileSnapshots) {
                if (quiet) {
                    echo("${info.timestamp}")
                } else {
                    val date = DATE_FMT.format(Instant.ofEpochMilli(info.timestamp))
                    val fileCount =
                        info.snapshot.mediaFilesCount + info.snapshot.documentFilesCount
                    echo("  Timestamp : ${info.timestamp}  ($date)")
                    echo("  User/device: ${info.userId}")
                    echo("  Files     : $fileCount")
                    echo("")
                }
            }
        }
    }

    private fun printAppSnapshot(info: SnapshotInfo) {
        val snap = info.snapshot
        val date = if (snap.token > 0) {
            DATE_FMT.format(Instant.ofEpochMilli(snap.token))
        } else {
            "unknown"
        }
        echo("  Hash      : ${info.hash}")
        echo("  Repo      : ${info.repoId}")
        echo("  Device    : ${snap.name} (Android ${snap.sdkInt})")
        echo("  Date      : ${snap.token}  ($date)")
        echo("  Apps      : ${snap.appsCount}")
        echo("")
    }
}
