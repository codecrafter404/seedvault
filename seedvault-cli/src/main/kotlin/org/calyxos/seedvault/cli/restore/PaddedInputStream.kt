/*
 * SPDX-FileCopyrightText: 2024 The Calyx Institute
 * SPDX-License-Identifier: Apache-2.0
 */

package org.calyxos.seedvault.cli.restore

import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * Wraps a decrypted stream and limits reads to the plaintext length encoded in the first 4 bytes.
 *
 * After decryption, the stream contains:
 * - 4 bytes  : signed 32-bit big-endian integer – the compressed plaintext size
 * - N bytes  : compressed plaintext (of that size)
 * - remaining: optional padding (discarded)
 *
 * This mirrors [com.stevesoltys.seedvault.repo.PaddedInputStream] from the app module.
 */
internal class PaddedInputStream(inputStream: InputStream) : FilterInputStream(inputStream) {

    private val size: Int
    private var bytesRead: Int = 0

    init {
        val sizeBytes = ByteArray(4)
        val read = inputStream.read(sizeBytes)
        if (read != 4) {
            throw IOException("Could not read padding size header (got $read bytes)")
        }
        size = ByteBuffer.wrap(sizeBytes).getInt()
        if (size < 0) {
            throw IOException("Invalid (negative) plaintext size in padding header: $size")
        }
    }

    override fun read(): Int {
        if (bytesRead >= size) return -1
        return getReadResult(super.read())
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (bytesRead >= size) return -1
        val toRead = if (bytesRead + len >= size) size - bytesRead else len
        return getReadResult(super.read(b, off, toRead))
    }

    override fun available(): Int = size - bytesRead

    private fun getReadResult(read: Int): Int {
        if (read == -1) return -1
        bytesRead += read
        if (bytesRead > size) return -1
        return read
    }
}
