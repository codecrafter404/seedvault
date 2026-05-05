/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.crypto

import cash.z.ecc.android.bip39.Mnemonics
import cash.z.ecc.android.bip39.Mnemonics.ChecksumException
import cash.z.ecc.android.bip39.Mnemonics.InvalidWordException
import cash.z.ecc.android.bip39.toSeed

/**
 * Converts a BIP39 mnemonic phrase into a [JvmKeyManager].
 *
 * The derivation matches what Seedvault does on-device:
 * 1. The 12-word phrase is validated and turned into a 64-byte seed via PBKDF2-SHA512.
 * 2. Bytes 32–63 of the seed are used as the HMAC-SHA256 main key for all further derivations.
 */
internal object MnemonicKeyDeriver {

    /**
     * Derives keys from the given [mnemonic].
     *
     * @param mnemonic space-separated 12-word BIP39 phrase (case-insensitive)
     * @throws InvalidWordException if any word is not in the BIP39 word list
     * @throws ChecksumException if the mnemonic checksum is invalid
     * @throws IllegalArgumentException if the word count is not 12
     */
    @Throws(InvalidWordException::class, ChecksumException::class, IllegalArgumentException::class)
    internal fun deriveFromMnemonic(mnemonic: String): JvmKeyManager {
        val trimmed = mnemonic.trim().lowercase()
        val code = Mnemonics.MnemonicCode(trimmed.toCharArray())
        code.validate()
        // toSeed() runs PBKDF2-HMAC-SHA512 with 2048 rounds and returns 64 bytes
        val seed = code.toSeed()
        return JvmKeyManager(seed)
    }
}
