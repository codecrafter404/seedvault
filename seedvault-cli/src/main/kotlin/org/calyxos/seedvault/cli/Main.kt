/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import org.calyxos.seedvault.cli.commands.DecryptAppCommand
import org.calyxos.seedvault.cli.commands.DecryptFilesCommand
import org.calyxos.seedvault.cli.commands.ListCommand

/**
 * Root command.  Sub-commands are registered via [subcommands].
 */
private class SeedvaultCli : CliktCommand(
    name = "seedvault-cli",
    help = """
        Cross-platform CLI tool for decrypting Seedvault backup repositories.

        Requires the 12-word BIP39 recovery phrase that was set up on the Android device.
        The mnemonic can be supplied via --mnemonic / -m or the SEEDVAULT_MNEMONIC
        environment variable; otherwise it is prompted interactively (input is hidden).

        Sub-commands:

          list          List all available snapshots (app and file backups).

          decrypt-app   Decrypt an app backup snapshot and extract app data tar files.

          decrypt-files Decrypt a file/media backup snapshot and restore the original files.
    """.trimIndent(),
) {
    override fun run() = Unit
}

fun main(args: Array<String>) {
    SeedvaultCli()
        .subcommands(ListCommand(), DecryptAppCommand(), DecryptFilesCommand())
        .main(args)
}
