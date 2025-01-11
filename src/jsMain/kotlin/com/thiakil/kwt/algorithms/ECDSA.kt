package com.thiakil.kwt.algorithms

import com.thiakil.kwt.JWS
import com.thiakil.kwt.JsonWebKey
import com.thiakil.kwt.JwsAlgorithm
import com.thiakil.kwt.SHAType
import com.thiakil.kwt.SigningKey
import com.thiakil.kwt.UnsupportedKeyException
import com.thiakil.kwt.UnverifiedSignature
import com.thiakil.kwt.algorithms.ecdsa.convertDERToRaw
import com.thiakil.kwt.algorithms.ecdsa.convertRawSigToDER
import com.thiakil.kwt.helpers.encodeBase64Url
import node.Crypto
import node.JSKeyObject
import node.KeyObject
import node.toKeyObjectPrivate
import node.toKeyObjectPublic
import node.toKotlinArray
import node.toPlatformArray

internal class EcdsaBase(override val jwaId: JWS.Id, shaType: SHAType): JwsAlgorithm {
    private val sigAlg = when(shaType) {
        SHAType.SHA256 -> "SHA256"
        SHAType.SHA384 -> "SHA384"
        SHAType.SHA512 -> "SHA512"
    }
    /** Size (in bytes) of the R,S integers. Equal to the size of the key */
    private val rsSize: Int = when(shaType) {
        SHAType.SHA256 -> 32
        SHAType.SHA384 -> 48
        SHAType.SHA512 -> 64
    }
    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        val publicKey = when(key) {
            is JSKeyObject -> key.key
            is JsonWebKey.EllipticCurve -> key.toKeyObjectPublic()
            else -> throw UnsupportedKeyException("Unknown key: $key")
        }
        if (publicKey.asymmetricKeyType != "ec") {
            throw UnsupportedKeyException("Not an EC key $key")
        }
        checkCurveType(jwaId, publicKey)
        val v = Crypto.createVerify(sigAlg)
        v.update(signature.subject, "utf8")
        return v.verify(publicKey, convertRawSigToDER(signature.signature, rsSize).toPlatformArray())
    }

    override fun sign(payload: String, key: SigningKey): String {
        val privateKey = when(key) {
            is JSKeyObject -> key.key
            is JsonWebKey.EllipticCurve -> key.toKeyObjectPrivate()
            else -> throw UnsupportedKeyException("Unknown key: $key")
        }
        if (privateKey.asymmetricKeyType != "ec") {
            throw UnsupportedKeyException("Not an EC key $key")
        }
        checkCurveType(jwaId, privateKey)
        val s = Crypto.createSign(sigAlg)
        s.update(payload, "utf8")
        return convertDERToRaw(s.sign(privateKey).toKotlinArray(), rsSize).encodeBase64Url()
    }

    private fun checkCurveType(jwaId: JWS.Id, key: KeyObject) {
        val expectedCurve = when (jwaId) {
            JWS.Id.ES256 -> "prime256"
            JWS.Id.ES384 -> "prime384"
            JWS.Id.ES512 -> "prime521"
            else -> throw IllegalStateException("Not ECDSA: $jwaId")
        }
        val namedCurve = key.asymmetricKeyDetails?.namedCurve
        if (namedCurve == null || !namedCurve.startsWith(expectedCurve)) {
            throw UnsupportedKeyException("Unknown or missing curve name '$namedCurve'")
        }
    }
}

public val ES256: JwsAlgorithm = EcdsaBase(JWS.Id.ES256, SHAType.SHA256)
public val ES384: JwsAlgorithm = EcdsaBase(JWS.Id.ES384, SHAType.SHA384)
public val ES512: JwsAlgorithm = EcdsaBase(JWS.Id.ES512, SHAType.SHA512)