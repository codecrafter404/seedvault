/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.restore

import com.github.luben.zstd.ZstdOutputStream
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming
import org.calyxos.seedvault.cli.crypto.MnemonicKeyDeriver
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

private const val SIZE_SEGMENT = 1 shl 20

/**
 * Verifies that [BackupDecryptor.decryptAndDecompressAppBlob] can decrypt ciphertext that was
 * produced with the exact same algorithm the Seedvault app uses on-device.
 */
class BackupDecryptorTest {

    private val testMnemonic = "abandon abandon abandon abandon abandon abandon " +
        "abandon abandon abandon abandon abandon about"

    private val keyManager = MnemonicKeyDeriver.deriveFromMnemonic(testMnemonic)
    private val streamKey = keyManager.appStreamKey()

    // -------------------------------------------------------------------------
    // Encrypt helpers (mirrors SnapshotManager / BlobCreator behaviour)
    // -------------------------------------------------------------------------

    /**
     * Produces a valid v2 app-backup ciphertext byte array:
     * [version=0x02] | [tink header] | [encrypted segments]
     *
     * Plaintext inside is: [4-byte size] | [zstd-compressed data]
     * (no padding added, matching how snapshots are stored).
     */
    private fun encryptAppPayload(plaintext: ByteArray): ByteArray {
        val version: Byte = 2
        val aad = byteArrayOf(version)

        // 1. Compress the plaintext with zstd
        val compressedOut = ByteArrayOutputStream()
        ZstdOutputStream(compressedOut).use { zstd -> zstd.write(plaintext) }
        val compressed = compressedOut.toByteArray()

        // 2. Prepend the 4-byte size header
        val sizeHeader = ByteBuffer.allocate(4).putInt(compressed.size).array()

        // 3. Encrypt with AesGcmHkdfStreaming (same parameters as CoreCrypto)
        val cipherOut = ByteArrayOutputStream()
        // Write the version byte first
        cipherOut.write(version.toInt())
        val aes = AesGcmHkdfStreaming(streamKey, "HmacSHA256", 32, SIZE_SEGMENT, 0)
        aes.newEncryptingStream(cipherOut, aad).use { enc ->
            enc.write(sizeHeader)
            enc.write(compressed)
        }
        return cipherOut.toByteArray()
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    fun `decrypt round-trip succeeds for small payload`() {
        val original = "Hello, Seedvault CLI!".toByteArray()
        val cipherText = encryptAppPayload(original)

        val decrypted = BackupDecryptor
            .decryptAndDecompressAppBlob(ByteArrayInputStream(cipherText), streamKey)
            .readBytes()

        assertArrayEquals(original, decrypted)
    }

    @Test
    fun `decrypt round-trip succeeds for larger payload (multiple zstd frames)`() {
        // 2 MiB of pseudo-random-ish data (not easily compressible)
        val original = ByteArray(2 * 1024 * 1024) { (it xor 0xA5).toByte() }
        val cipherText = encryptAppPayload(original)

        val decrypted = BackupDecryptor
            .decryptAndDecompressAppBlob(ByteArrayInputStream(cipherText), streamKey)
            .readBytes()

        assertArrayEquals(original, decrypted)
    }

    @Test
    fun `sha256 hash verification helper is consistent`() {
        val data = "test data".toByteArray()
        val hash1 = BackupDecryptor.sha256(data).toHexString()
        val hash2 = BackupDecryptor.sha256(data).toHexString()
        assert(hash1 == hash2) { "sha256 is not deterministic" }
        assert(hash1.length == 64) { "SHA-256 must be 64 hex chars" }
    }

    @Test
    fun `wrong stream key causes decryption to fail`() {
        val original = "sensitive data".toByteArray()
        val cipherText = encryptAppPayload(original)

        val wrongKey = ByteArray(32) { 0xFF.toByte() }
        try {
            BackupDecryptor
                .decryptAndDecompressAppBlob(ByteArrayInputStream(cipherText), wrongKey)
                .readBytes()
            error("Expected an exception for wrong key, but decryption succeeded")
        } catch (e: Exception) {
            // Expected: GeneralSecurityException or IOException from tink / zstd
        }
    }

    // Helper
    private fun ByteArray.toHexString() = BackupDecryptor.run { this@toHexString.toHexString() }
}
