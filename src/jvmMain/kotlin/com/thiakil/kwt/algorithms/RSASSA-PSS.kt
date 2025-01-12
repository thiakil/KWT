

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
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

private val SHAType.mdName get() = when(this) {
    SHAType.SHA256 -> "SHA-256"
    SHAType.SHA384 -> "SHA-384"
    SHAType.SHA512 -> "SHA-512"
    SHAType.NONE -> throw IllegalArgumentException("NONE is not valid")
}
private val SHAType.mfgSpec get() = when(this) {
    SHAType.SHA256 -> MGF1ParameterSpec.SHA256
    SHAType.SHA384 -> MGF1ParameterSpec.SHA384
    SHAType.SHA512 -> MGF1ParameterSpec.SHA512
    SHAType.NONE -> throw IllegalArgumentException("NONE is not valid")
}
private val SHAType.saltLen get() = when(this) {
    SHAType.SHA256 -> 32
    SHAType.SHA384 -> 48
    SHAType.SHA512 -> 64
    SHAType.NONE -> throw IllegalArgumentException("NONE is not valid")
}

public sealed class RsassPssBase(override val jwaId: JWS.Id, alg: SHAType): JwsAlgorithm {
    private val pssParameterSpec = PSSParameterSpec(alg.mdName, "MGF1", alg.mfgSpec, alg.saltLen, 1)

    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        val publicKey = when(key) {
            is JavaRSAKey -> key.publicKey ?: throw UnsupportedKeyException("No public key!")
            is JsonWebKey.RSA -> key.toJavaRSAPublicKey()
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance("RSASSA-PSS")
        s.setParameter(pssParameterSpec)
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
        val s = Signature.getInstance("RSASSA-PSS")
        s.setParameter(pssParameterSpec)
        s.initSign(privateKey, SecureRandom())
        s.update(payload.toByteArray(Charsets.UTF_8))
        return s.sign().encodeBase64Url()
    }
}

public data object PS256: RsassPssBase(JWS.Id.PS256, SHAType.SHA256)
public data object PS384: RsassPssBase(JWS.Id.PS384, SHAType.SHA384)
public data object PS512: RsassPssBase(JWS.Id.PS512, SHAType.SHA512)
