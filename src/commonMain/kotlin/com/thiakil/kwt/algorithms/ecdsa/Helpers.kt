package com.thiakil.kwt.algorithms.ecdsa

import com.thiakil.kwt.InvalidSignatureException
import com.thiakil.kwt.JWS
import io.ktor.utils.io.core.buildPacket
import io.ktor.utils.io.core.writeFully
import kotlinx.io.readByteArray
import kotlin.math.max
import kotlin.math.min

internal val JWS.Id.curveOid
    get() = when (this) {
        JWS.Id.ES256 -> "1.2.840.10045.3.1.7"
        JWS.Id.ES384 -> "1.3.132.0.34"
        JWS.Id.ES512 -> "1.3.132.0.35"
        else -> ""
    }

/**
 * Converts from raw {R,S} signature format to DER-encoded like Java expects
 */
internal fun convertRawSigToDER(rawSignature: ByteArray, rsSize: Int): ByteArray {
    if (rawSignature.size != rsSize * 2) {
        throw InvalidSignatureException("Size mismatch for algorithm. Expected ${rsSize * 2}, got ${rawSignature.size}")
    }

    // Retrieve R and S number's length and padding.
    val rPadding: Int = countPadding(rawSignature, 0, rsSize)
    val sPadding: Int = countPadding(rawSignature, rsSize, rawSignature.size)
    val rLength: Int = rsSize - rPadding
    val sLength: Int = rsSize - sPadding
    val length = 2 + rLength + 2 + sLength
    if (length > 255) {
        throw InvalidSignatureException("Expected compressed length <= 255")
    }

    return buildPacket {
        // DER Structure: http://crypto.stackexchange.com/a/1797
        // Header with signature length info
        writeByte(0x30)
        if (length > 0x7f){
            writeByte(0x81.toByte())
        }
        writeByte((length and 0xff).toByte())

        // Header with "min R" number length
        writeByte(0x02)
        writeByte(rLength.toByte())

        // R number
        if (rPadding < 0) {
            writeByte(0)
            writeFully(buffer= rawSignature, offset=0, length=rsSize)
        } else {
            writeFully(buffer = rawSignature, offset = rPadding, length = min(rsSize, rLength))
        }

        // Header with "min S" number length
        writeByte(0x02)
        writeByte(sLength.toByte())

        // S number
        if (sPadding < 0) {
            writeByte(0)
            writeFully(buffer=rawSignature, offset=rsSize, length=rsSize)
        } else {
            writeFully(buffer=rawSignature, offset=rsSize+sPadding, length= min(rsSize, sLength))
        }

    }.readByteArray()
}

internal fun convertDERToRaw(derSignature: ByteArray, rsSize: Int): ByteArray {
    // DER Structure: http://crypto.stackexchange.com/a/1797
    val derEncoded = derSignature[0] == 0x30.toByte() && derSignature.size != rsSize * 2
    if (!derEncoded) {
        throw InvalidSignatureException("Invalid DER signature format.")
    }

    val joseSignature = ByteArray(rsSize * 2)

    //Skip 0x30
    var offset = 1
    if (derSignature[1] == 0x81.toByte()) {
        //Skip sign
        offset++
    }

    //Convert to unsigned. Should match DER length - offset
    val encodedLength: Int = derSignature[offset++].toInt() and 0xff
    if (encodedLength != derSignature.size - offset) {
        throw InvalidSignatureException("Invalid DER signature format.")
    }

    //Skip 0x02
    offset++

    //Obtain R number length (Includes padding) and skip it
    val rLength = derSignature[offset++].toInt()
    if (rLength > rsSize + 1) {
        throw InvalidSignatureException("Invalid DER signature format.")
    }
    val rPadding: Int = rsSize - rLength
    //Retrieve R number
    derSignature.copyInto(
        destination = joseSignature,
        destinationOffset = max(rPadding, 0),
        startIndex = offset + max(-rPadding, 0),
        endIndex = offset + max(-rPadding, 0) + rLength + min(rPadding, 0)
    )
    //System.arraycopy(
    //    derSignature,//src
    //    offset + max(-rPadding, 0),//srcpos
    //    joseSignature,//dest
    //    max(rPadding, 0),//destpos
    //    rLength + min(rPadding, 0)//length
    //)

    //Skip R number and 0x02
    offset += rLength + 1

    //Obtain S number length. (Includes padding)
    val sLength = derSignature[offset++].toInt()
    if (sLength > rsSize + 1) {
        throw InvalidSignatureException("Invalid DER signature format.")
    }
    val sPadding: Int = rsSize - sLength
    //Retrieve R number
    val srcPos = offset + max(-sPadding, 0)
    val destPos = rsSize + max(sPadding, 0)
    val length = sLength + min(sPadding, 0)
    derSignature.copyInto(
        destination = joseSignature,
        destinationOffset = destPos,
        startIndex = srcPos,
        endIndex = srcPos + length
    )
    //System.arraycopy(
    //    derSignature,
    //    srcPos,
    //    joseSignature,
    //    destPos,
    //    length
    //)

    return joseSignature
}

private fun countPadding(bytes: ByteArray, fromIndex: Int, toIndex: Int): Int {
    var padding = 0
    while (fromIndex + padding < toIndex && bytes[fromIndex + padding] == 0.toByte()) {
        padding++
    }
    return if (bytes[fromIndex + padding].toInt() and 0xff > 0x7f) padding - 1 else padding
}