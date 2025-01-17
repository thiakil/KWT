package com.thiakil.kwt.algorithms

import com.thiakil.kwt.JWS
import com.thiakil.kwt.JsonWebKey
import com.thiakil.kwt.JwsAlgorithm
import com.thiakil.kwt.SHAType
import com.thiakil.kwt.SigningKey
import com.thiakil.kwt.UnsupportedKeyException
import com.thiakil.kwt.UnverifiedSignature
import com.thiakil.kwt.helpers.encodeBase64Url
import node.Crypto
import node.toKotlinArray
import node.toPlatformArray

internal class HmacBase(override val jwaId: JWS.Id, alg: SHAType): JwsAlgorithm {
    private val nodeAlg = when(alg) {
        SHAType.SHA256 -> "sha256"
        SHAType.SHA384 -> "sha384"
        SHAType.SHA512 -> "sha512"
        SHAType.NONE -> throw IllegalArgumentException("NONE is not valid")
    }

    private fun createDigest(data: String, key: SigningKey): ByteArray {
        val keyBytes = when (key) {
            is JsonWebKey.Symmetric -> key.keyValue
            is HmacKey -> key.secretBytes
            else -> throw UnsupportedKeyException("Unknown key type")
        }
        val hmac = Crypto.createHmac(nodeAlg, keyBytes.toPlatformArray())
        hmac.update(data, "utf8")
        return hmac.digest().toKotlinArray()
    }

    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        val digest = createDigest(signature.subject, key)
        return signature.signature.contentEquals(digest)
    }

    override fun sign(payload: String, key: SigningKey): String {
        return createDigest(payload, key).encodeBase64Url()
    }
}

public val HS256: JwsAlgorithm = HmacBase(JWS.Id.HS256, SHAType.SHA256)
public val HS384: JwsAlgorithm = HmacBase(JWS.Id.HS384, SHAType.SHA384)
public val HS512: JwsAlgorithm = HmacBase(JWS.Id.HS512, SHAType.SHA512)