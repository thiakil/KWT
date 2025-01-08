

package com.thiakil.kwt.algorithms

import com.thiakil.kwt.SigningKey
import com.thiakil.kwt.*
import com.thiakil.kwt.helpers.encodeBase64Url
import java.security.*

public sealed class RSABase(override val jwaId: String, alg: SHAType): JwsAlgorithm {
    private val javaSigAlg = when(alg) {
        SHAType.SHA256 -> "SHA256withRSA"
        SHAType.SHA384 -> "SHA384withRSA"
        SHAType.SHA512 -> "SHA512withRSA"
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

public object RS256: RSABase("RS256", SHAType.SHA256)
public object RS384: RSABase("RS384", SHAType.SHA384)
public object RS512: RSABase("RS512", SHAType.SHA512)
