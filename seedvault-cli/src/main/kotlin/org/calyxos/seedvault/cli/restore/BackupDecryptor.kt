/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.restore

import com.github.luben.zstd.ZstdInputStream
import com.google.crypto.tink.subtle.AesGcmHkdfStreaming
import java.io.InputStream
import java.security.GeneralSecurityException
import java.security.MessageDigest

private const val KEY_SIZE_BYTES = 32
private const val ALGORITHM_HMAC = "HmacSHA256"
private const val SIZE_SEGMENT = 1 shl 20 // 1 MiB, must match CoreCrypto.SIZE_SEGMENT

/**
 * Low-level helpers shared by app-backup and file-backup decryptors.
 *
 * Encryption format for every file in the repository:
 * ```
 *  [version byte] | [tink AesGcmHkdfStreaming ciphertext]
 * ```
 * where the tink header is 40 bytes: header_length (1) + salt (32) + nonce_prefix (7).
 *
 * After decryption of an **app backup** blob the plaintext is:
 * ```
 *  [4 bytes signed int32 plaintext size] | [zstd-compressed data] | [optional padding]
 * ```
 */
internal object BackupDecryptor {

    /**
     * Returns an [InputStream] that decrypts then decompresses an **app backup** blob or snapshot.
     *
     * @param rawStream  raw ciphertext stream starting with the 1-byte version field
     * @param streamKey  the 256-bit stream key (HKDF-derived from the main key)
     *
     * The caller is responsible for closing the returned stream.
     */
    @Throws(GeneralSecurityException::class)
    internal fun decryptAndDecompressAppBlob(
        rawStream: InputStream,
        streamKey: ByteArray,
    ): InputStream {
        // Read and validate the version byte
        val version = rawStream.read()
        check(version != -1) { "Empty stream – no version byte found" }
        check(version == 2) { "Unsupported app backup version: $version (expected 2)" }

        // The version byte is used as authenticated associated data (AAD)
        val aad = byteArrayOf(version.toByte())

        val decryptingStream = newDecryptingStream(streamKey, rawStream, aad)
        val paddedStream = PaddedInputStream(decryptingStream)
        return ZstdInputStream(paddedStream)
    }

    /**
     * Returns an [InputStream] that decrypts a **file backup** chunk or snapshot.
     *
     * Unlike app backups, file backup streams are NOT padded and NOT zstd-compressed at the
     * stream level (the compression is handled inside the zip or individually per file).
     *
     * @param rawStream  raw ciphertext stream starting with the 1-byte version field
     * @param streamKey  the 256-bit stream key (HKDF-derived from the main key)
     * @param associatedData  AAD bytes that authenticate the stream (chunk-id or snapshot timestamp)
     *
     * The caller is responsible for closing the returned stream.
     */
    @Throws(GeneralSecurityException::class)
    internal fun decryptFileStream(
        rawStream: InputStream,
        streamKey: ByteArray,
        associatedData: ByteArray,
    ): InputStream {
        // Read and validate the version byte (file backup uses version 0)
        val version = rawStream.read()
        check(version != -1) { "Empty stream – no version byte found" }
        check(version in 0..0) { "Unsupported file backup version: $version (expected 0)" }

        return newDecryptingStream(streamKey, rawStream, associatedData)
    }

    /**
     * Returns the raw decrypting stream backed by [AesGcmHkdfStreaming].
     * Mirrors [org.calyxos.seedvault.core.crypto.CoreCrypto.newDecryptingStream].
     */
    @Throws(GeneralSecurityException::class)
    internal fun newDecryptingStream(
        streamKey: ByteArray,
        inputStream: InputStream,
        associatedData: ByteArray,
    ): InputStream {
        return AesGcmHkdfStreaming(
            streamKey,
            ALGORITHM_HMAC,
            KEY_SIZE_BYTES,
            SIZE_SEGMENT,
            0,
        ).newDecryptingStream(inputStream, associatedData)
    }

    /** SHA-256 hash of [bytes] – used to verify file integrity before decryption. */
    internal fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    /** Formats a [ByteArray] as a lower-case hex string. */
    internal fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
}
