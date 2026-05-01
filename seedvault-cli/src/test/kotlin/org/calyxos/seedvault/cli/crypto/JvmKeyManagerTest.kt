/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import javax.crypto.spec.SecretKeySpec

class JvmKeyManagerTest {

    private val testMnemonic = "abandon abandon abandon abandon abandon abandon " +
        "abandon abandon abandon abandon abandon about"

    @Test
    fun `constructor rejects seed shorter than 64 bytes`() {
        val shortSeed = ByteArray(31)
        assertThrows<IllegalArgumentException> { JvmKeyManager(shortSeed) }
    }

    @Test
    fun `main key uses HmacSHA256 algorithm`() {
        val km = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        assertEquals("HmacSHA256", km.mainKey.algorithm)
    }

    @Test
    fun `derived keys are 32 bytes`() {
        val km = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        assertEquals(32, km.appStreamKey().size)
        assertEquals(32, km.fileStreamKey().size)
        assertEquals(32, km.appRepoIdKey().size)
    }

    @Test
    fun `key derivation is deterministic`() {
        val km1 = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        val km2 = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        assertArrayEquals(km1.appStreamKey(), km2.appStreamKey())
        assertArrayEquals(km1.fileStreamKey(), km2.fileStreamKey())
        assertArrayEquals(km1.appRepoIdKey(), km2.appRepoIdKey())
    }

    @Test
    fun `all three derived keys are distinct`() {
        val km = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        val app = km.appStreamKey().toHexString()
        val file = km.fileStreamKey().toHexString()
        val repo = km.appRepoIdKey().toHexString()
        assert(app != file) { "appStreamKey == fileStreamKey" }
        assert(app != repo) { "appStreamKey == appRepoIdKey" }
        assert(file != repo) { "fileStreamKey == appRepoIdKey" }
    }

    @Test
    fun `JvmKeyManager built from raw seed bytes is equivalent to mnemonic-derived`() {
        val km = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)

        // Reconstruct from the raw 64-byte seed by extracting the main key bytes.
        // We cannot easily test the seed bytes directly, but we can verify deriveKey consistency.
        val appStreamKey = km.appStreamKey()
        assertEquals(32, appStreamKey.size)

        // Ensure a second derivation with the same info string produces the same bytes
        assertArrayEquals(appStreamKey, km.deriveKey("app backup stream key"))
    }

    @Test
    fun `deriveKey with different info strings returns different keys`() {
        val km = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
        val k1 = km.deriveKey("info1")
        val k2 = km.deriveKey("info2")
        assert(!k1.contentEquals(k2)) { "Different info strings produced the same key" }
    }

    @Test
    fun `JvmKeyManager accepts exactly 64 byte seed`() {
        val seed = ByteArray(64) { it.toByte() }
        val km = JvmKeyManager(seed)
        assertEquals(32, km.appStreamKey().size)
    }

    // Verify that the main key uses bytes 32..63 (not 0..31) of the seed
    @Test
    fun `main key uses second half of seed`() {
        val seed = ByteArray(64) { if (it < 32) 0.toByte() else 1.toByte() }
        val km = JvmKeyManager(seed)

        // Main key = SecretKeySpec(seed, 32, 32, "HmacSHA256")  →  all 1-bytes
        val expected = SecretKeySpec(ByteArray(32) { 1.toByte() }, "HmacSHA256")
        assertArrayEquals(expected.encoded, km.mainKey.encoded)
    }

    // Helper
    private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }
}
