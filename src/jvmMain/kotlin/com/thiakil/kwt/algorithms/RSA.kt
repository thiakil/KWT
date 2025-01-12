

package com.thiakil.kwt.algorithms

import com.thiakil.kwt.JWS
import com.thiakil.kwt.JsonWebKey
import com.thiakil.kwt.JwsAlgorithm
import com.thiakil.kwt.SHAType
import com.thiakil.kwt.SigningKey
import com.thiakil.kwt.UnsupportedKeyException
import com.thiakil.kwt.UnverifiedSignature
import com.thiakil.kwt.helpers.encodeBase64Url
import java.security.SecureRandom
import java.security.Signature

public sealed class RSABase(override val jwaId: JWS.Id, alg: SHAType): JwsAlgorithm {
    private val javaSigAlg = when(alg) {
        SHAType.SHA256 -> "SHA256withRSA"
        SHAType.SHA384 -> "SHA384withRSA"
        SHAType.SHA512 -> "SHA512withRSA"
        SHAType.NONE -> throw IllegalArgumentException("NONE is not valid")
    }
    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        val publicKey = when(key) {
            is JavaRSAKey -> key.publicKey ?: throw UnsupportedKeyException("No public key!")
            is JsonWebKey.RSA -> key.toJavaRSAPublicKey()
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance(javaSigAlg)
        s.initVerify(publicKey)
        s.update(signature.subject.toByteArray(Charsets.UTF_8))
        return s.verify(signature.signature)
    }

    override fun sign(payload: String, key: SigningKey): String {
        val privateKey = when(key) {
            is JavaRSAKey -> key.privateKey ?: throw UnsupportedKeyException("No private key!")
            is JsonWebKey.RSA -> key.toJavaRSAPrivateKey()
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance(javaSigAlg)
        s.initSign(privateKey, SecureRandom())
        s.update(payload.toByteArray(Charsets.UTF_8))
        return s.sign().encodeBase64Url()
    }
}

public data object RS256: RSABase(JWS.Id.RS256, SHAType.SHA256)
public data object RS384: RSABase(JWS.Id.RS384, SHAType.SHA384)
public data object RS512: RSABase(JWS.Id.RS512, SHAType.SHA512)
