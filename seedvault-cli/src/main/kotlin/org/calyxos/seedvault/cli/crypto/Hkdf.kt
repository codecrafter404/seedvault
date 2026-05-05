/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.crypto

import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import javax.crypto.Mac
import javax.crypto.SecretKey
import kotlin.math.ceil
import kotlin.math.min

/**
 * HKDF expand step (RFC 5869, Section 2.3) using HMAC-SHA256.
 *
 * This mirrors [org.calyxos.seedvault.core.crypto.Hkdf] from the :core module
 * but is kept here as a standalone implementation to avoid Android transitive dependencies.
 */
internal object Hkdf {

    private const val ALGORITHM_HMAC = "HmacSHA256"

    /**
     * Expands a pseudorandom key (PRK) into output keying material.
     *
     * @param secretKey the pseudorandom key (usually the main key)
     * @param info optional context / application-specific information
     * @param outLengthBytes desired output length in bytes
     */
    @Throws(GeneralSecurityException::class)
    internal fun expand(secretKey: SecretKey, info: ByteArray?, outLengthBytes: Int): ByteArray {
        require(outLengthBytes > 0) { "out length bytes must be at least 1" }

        val hmacHasher: Mac = Mac.getInstance(ALGORITHM_HMAC).apply { init(secretKey) }

        val iterations = ceil(outLengthBytes.toDouble() / hmacHasher.macLength).toInt()
        require(iterations <= 255) {
            "out length must be maximal 255 * hash-length; requested: $outLengthBytes bytes"
        }

        val buffer: ByteBuffer = ByteBuffer.allocate(outLengthBytes)
        var blockN = ByteArray(0)
        var remainingBytes = outLengthBytes
        for (i in 0 until iterations) {
            hmacHasher.update(blockN)
            hmacHasher.update(info ?: ByteArray(0))
            hmacHasher.update((i + 1).toByte())
            blockN = hmacHasher.doFinal()
            val stepSize = min(remainingBytes, blockN.size)
            buffer.put(blockN, 0, stepSize)
            remainingBytes -= stepSize
        }
        return buffer.array()
    }
}
