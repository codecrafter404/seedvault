/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.crypto

import java.security.GeneralSecurityException
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

private const val KEY_SIZE_BYTES = 32

/**
 * Holds the seed-derived keys in memory (no Android KeyStore involved).
 *
 * Created from the 64-byte BIP39 seed:
 * - bytes  0–31: legacy backup key (AES-256, kept for reference)
 * - bytes 32–63: main key used as HMAC-SHA256 for HKDF-based sub-key derivation
 *
 * The main key is the same key that [com.stevesoltys.seedvault.crypto.KeyManagerImpl]
 * imports into the Android KeyStore under `com.stevesoltys.seedvault.main`.
 */
internal class JvmKeyManager(seed: ByteArray) {

    init {
        require(seed.size >= KEY_SIZE_BYTES * 2) {
            "Seed must be at least ${KEY_SIZE_BYTES * 2} bytes (got ${seed.size})"
        }
    }

    /** The main key (bytes 32–63 of the BIP39 seed), used as an HMAC-SHA256 key for HKDF. */
    val mainKey: SecretKey =
        SecretKeySpec(seed, KEY_SIZE_BYTES, KEY_SIZE_BYTES, "HmacSHA256")

    /**
     * Derives a 256-bit sub-key from the main key using HKDF expand.
     *
     * @param info UTF-8 info string matching those used in [CryptoImpl] / [StreamCrypto].
     */
    @Throws(GeneralSecurityException::class)
    fun deriveKey(info: String): ByteArray =
        Hkdf.expand(mainKey, info.toByteArray(Charsets.UTF_8), KEY_SIZE_BYTES)

    /**
     * Derives the stream key used to encrypt/decrypt app backup streams (v2).
     * Matches `CryptoImpl.streamKey` on device.
     */
    @Throws(GeneralSecurityException::class)
    fun appStreamKey(): ByteArray = deriveKey("app backup stream key")

    /**
     * Derives the repo-ID HMAC key used to compute the repository folder name.
     * Matches `CryptoImpl.repoId` on device.
     */
    @Throws(GeneralSecurityException::class)
    fun appRepoIdKey(): ByteArray = deriveKey("app backup repoId key")

    /**
     * Derives the stream key used to encrypt/decrypt file/media backup streams.
     * Matches `StreamCrypto.deriveStreamKey` on device.
     */
    @Throws(GeneralSecurityException::class)
    fun fileStreamKey(): ByteArray = deriveKey("stream key")
}
