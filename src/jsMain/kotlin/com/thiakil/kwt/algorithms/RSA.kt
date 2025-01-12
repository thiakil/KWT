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
import node.JSKeyObject
import node.toKeyObjectPublic
import node.toKeyObjectPrivate
import node.toKotlinArray
import node.toPlatformArray

internal class RSABase(override val jwaId: JWS.Id, alg: SHAType): JwsAlgorithm {
    private val sigAlg = when(alg) {
        SHAType.SHA256 -> "SHA256"
        SHAType.SHA384 -> "SHA384"
        SHAType.SHA512 -> "SHA512"
        SHAType.NONE -> throw IllegalArgumentException("NONE is not valid")
    }
    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        val publicKey = when(key) {
            is JSKeyObject -> key.key
            is JsonWebKey.RSA -> key.toKeyObjectPublic()
            else -> throw UnsupportedKeyException("Unknown key: $key")
        }
        if (publicKey.asymmetricKeyType != "rsa") {
            throw UnsupportedKeyException("Not an RSA key $key")
        }
        val v = Crypto.createVerify(sigAlg)
        v.update(signature.subject, "utf8")
        return v.verify(publicKey, signature.signature.toPlatformArray())
    }

    override fun sign(payload: String, key: SigningKey): String {
        val privateKey = when(key) {
            is JSKeyObject -> key.key
            is JsonWebKey.RSA -> key.toKeyObjectPrivate()
            else -> throw UnsupportedKeyException("Unknown key: $key")
        }
        if (privateKey.asymmetricKeyType != "rsa") {
            throw UnsupportedKeyException("Not an RSA key $key")
        }
        val s = Crypto.createSign(sigAlg)
        s.update(payload, "utf8")
        return s.sign(privateKey).toKotlinArray().encodeBase64Url()
    }
}

public val RS256: JwsAlgorithm = RSABase(JWS.Id.RS256, SHAType.SHA256)
public val RS384: JwsAlgorithm = RSABase(JWS.Id.RS384, SHAType.SHA384)
public val RS512: JwsAlgorithm = RSABase(JWS.Id.RS512, SHAType.SHA512)