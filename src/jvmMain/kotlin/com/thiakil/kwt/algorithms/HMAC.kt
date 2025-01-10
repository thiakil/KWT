

package com.thiakil.kwt.algorithms

import com.thiakil.kwt.JWS
import com.thiakil.kwt.JsonWebKey
import com.thiakil.kwt.JwsAlgorithm
import com.thiakil.kwt.SHAType
import com.thiakil.kwt.SigningKey
import com.thiakil.kwt.UnsupportedKeyException
import com.thiakil.kwt.UnverifiedSignature
import com.thiakil.kwt.helpers.encodeBase64Url
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

public interface HmacKey: SigningKey {
    public val secretBytes: ByteArray
}

public class HmacByteKey(override val secretBytes: ByteArray): HmacKey

public data class HmacStringKey(val secret: String): HmacKey {
    override val secretBytes: ByteArray
        get() = secret.toByteArray(Charsets.UTF_8)
}

public sealed class HmacBase(override val jwaId: JWS.Id, alg: SHAType): JwsAlgorithm {
    private val javaSigAlg = when(alg) {
        SHAType.SHA256 -> "HmacSHA256"
        SHAType.SHA384 -> "HmacSHA384"
        SHAType.SHA512 -> "HmacSHA512"
    }
    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        return MessageDigest.isEqual(doMac(key, signature.subject), signature.signature)
    }

    private fun doMac(key: SigningKey, subject: String): ByteArray {
        val keyBytes = when (key) {
            is JsonWebKey.Symmetric -> key.keyValue
            is HmacKey -> key.secretBytes
            else -> throw UnsupportedKeyException("Unknown key: " + key.javaClass.name)
        }
        val mac = Mac.getInstance(javaSigAlg)
        mac.init(SecretKeySpec(keyBytes, javaSigAlg))
        return mac.doFinal(subject.toByteArray(Charsets.UTF_8))
    }

    override fun sign(payload: String, key: SigningKey): String = doMac(key, payload).encodeBase64Url()
}

public data object HS256: HmacBase(JWS.Id.HS256, SHAType.SHA256)
public data object HS384: HmacBase(JWS.Id.HS384, SHAType.SHA384)
public data object HS512: HmacBase(JWS.Id.HS512, SHAType.SHA512)
