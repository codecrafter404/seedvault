/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class MnemonicKeyDeriverTest {

    /**
     * 12-word test mnemonic from the Seedvault app test suite.
     * ("abandon" repeated 11 times + "about" is a well-known BIP39 test vector.)
     */
    private val testMnemonic = "abandon abandon abandon abandon abandon abandon " +
        "abandon abandon abandon abandon abandon about"

    @Test
    fun `deriveFromMnemonic returns a JvmKeyManager for valid mnemonic`() {
        val manager = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        // Main key must not be null and must be HmacSHA256
        assertEquals("HmacSHA256", manager.mainKey.algorithm)
    }

    @Test
    fun `same mnemonic produces same keys`() {
        val km1 = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        val km2 = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        assertEquals(
            km1.appStreamKey().toHexString(),
            km2.appStreamKey().toHexString(),
        )
        assertEquals(
            km1.fileStreamKey().toHexString(),
            km2.fileStreamKey().toHexString(),
        )
    }

    @Test
    fun `different mnemonics produce different keys`() {
        val mnemonic2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        val km1 = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        val km2 = MnemonicKeyDeriver.deriveFromMnemonic(mnemonic2)
        assertNotEquals(
            km1.appStreamKey().toHexString(),
            km2.appStreamKey().toHexString(),
        )
    }

    @Test
    fun `app stream key and file stream key are different`() {
        val km = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        assertNotEquals(
            km.appStreamKey().toHexString(),
            km.fileStreamKey().toHexString(),
        )
    }

    @Test
    fun `mnemonic with wrong checksum throws ChecksumException`() {
        // Change the last word to invalidate the checksum
        val badMnemonic = "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon zoo"
        assertThrows<cash.z.ecc.android.bip39.Mnemonics.ChecksumException> {
            MnemonicKeyDeriver.deriveFromMnemonic(badMnemonic)
        }
    }

    @Test
    fun `mnemonic with unknown word throws InvalidWordException`() {
        val badMnemonic = "notaword abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about"
        assertThrows<cash.z.ecc.android.bip39.Mnemonics.InvalidWordException> {
            MnemonicKeyDeriver.deriveFromMnemonic(badMnemonic)
        }
    }

    @Test
    fun `leading and trailing whitespace is tolerated`() {
        val padded = "  $testMnemonic  "
        val km1 = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        val km2 = MnemonicKeyDeriver.deriveFromMnemonic(padded)
        assertEquals(
            km1.appStreamKey().toHexString(),
            km2.appStreamKey().toHexString(),
        )
    }

    @Test
    fun `uppercase mnemonic is accepted`() {
        val upper = testMnemonic.uppercase()
        val km = MnemonicKeyDeriver.deriveFromMnemonic(upper)
        val kmLower = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        assertEquals(
            km.appStreamKey().toHexString(),
            kmLower.appStreamKey().toHexString(),
        )
    }

    // Helper
    private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }
}
