/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.commands

import com.github.ajalt.clikt.core.CliktCommand

/**
 * Prompts the user for the 12-word BIP39 mnemonic, hiding input where the terminal supports it.
 *
 * The entered string is never stored on disk or logged.
 */
internal fun CliktCommand.promptMnemonic(): String {
    val console = System.console()
    return if (console != null) {
        // Console.readPassword hides the input (no echo)
        val chars = console.readPassword("Enter 12-word recovery phrase: ")
            ?: throw RuntimeException("Could not read mnemonic from console")
        String(chars).also { chars.fill(' ') }
    } else {
        // Fallback for IDEs / piped input where System.console() is null
        print("Enter 12-word recovery phrase: ")
        readLine() ?: throw RuntimeException("Could not read mnemonic from stdin")
    }
}
