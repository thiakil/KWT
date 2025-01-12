

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
import com.thiakil.kwt.algorithms.ecdsa.curveOid
import com.thiakil.kwt.helpers.encodeBase64Url
import java.lang.IllegalArgumentException
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.Key
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import kotlin.text.toByteArray


private val JsonWebKey.EllipticCurve.ecParameterSpec: ECParameterSpec
    get() {
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(
            ECGenParameterSpec(
                when (curve) {
                    "P-256" -> "secp256r1"
                    "P-384" -> "secp384r1"
                    "P-521" -> "secp521r1"
                    else -> throw UnsupportedKeyException("Unknown curve: $curve")
                }
            )
        )
        return parameters.getParameterSpec(ECParameterSpec::class.java)!!
    }

internal fun JsonWebKey.EllipticCurve.toJavaPublic(): ECPublicKey {
    val pubPoint = ECPoint(BigInteger(1, x), BigInteger(1, y))
    val pubSpec = ECPublicKeySpec(pubPoint, ecParameterSpec)
    val kf = KeyFactory.getInstance("EC")
    return kf.generatePublic(pubSpec) as ECPublicKey
}

internal fun JsonWebKey.EllipticCurve.toJavaPrivate(): ECPrivateKey {
    val privateSpec = ECPrivateKeySpec(BigInteger(1, eccPrivateKey ?: throw IllegalArgumentException("No private key")), ecParameterSpec)
    val kf = KeyFactory.getInstance("EC")
    return kf.generatePrivate(privateSpec) as ECPrivateKey
}

private fun curveOid(key: Key): String? {
    try {
        val params = AlgorithmParameters.getInstance("EC")
        params.init((key as ECKey).params)
        return params.getParameterSpec(ECGenParameterSpec::class.java).name
    } catch (e: Exception) {
        return null
    }
}

public data class JavaECKey(val publicKey: ECPublicKey? = null, val privateKey: ECPrivateKey? = null): SigningKey

public sealed class EcdsaBase(override val jwaId: JWS.Id, shaType: SHAType): JwsAlgorithm {
    /** Size (in bytes) of the R,S integers. Equal to the size of the key */
    private val rsSize: Int = when(shaType) {
        SHAType.SHA256 -> 32
        SHAType.SHA384 -> 48
        SHAType.SHA512 -> 66
        else -> -1
    }
    private val javaSigAlg = when(shaType) {
        SHAType.SHA256 -> "SHA256withECDSA"
        SHAType.SHA384 -> "SHA384withECDSA"
        SHAType.SHA512 -> "SHA512withECDSA"
        SHAType.NONE -> "INVALID"
    }

    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        val publicKey: ECPublicKey = when(key) {
            is JsonWebKey.EllipticCurve -> key.toJavaPublic()
            is JavaECKey -> key.publicKey ?:
            throw UnsupportedKeyException("No public key")
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val s = Signature.getInstance(javaSigAlg)
        s.initVerify(publicKey)
        s.update(signature.subject.toByteArray(Charsets.UTF_8))
        return s.verify(convertRawSigToDER(signature.signature, rsSize))
    }

    override fun sign(payload: String, key: SigningKey): String {
        val privateKey: ECPrivateKey = when(key) {
            is JsonWebKey.EllipticCurve -> key.toJavaPrivate()
            is JavaECKey -> key.privateKey ?: throw UnsupportedKeyException("No private key")
            else -> throw UnsupportedKeyException("Unknown key: "+key.javaClass.name)
        }
        val curveOid = curveOid(privateKey)
        if (curveOid != null && jwaId.curveOid != curveOid) {
            throw UnsupportedKeyException("Incorrect curve. Expected oid ${jwaId.curveOid} but found $curveOid")
        }
        val s = Signature.getInstance(javaSigAlg)
        s.initSign(privateKey, SecureRandom())
        s.update(payload.toByteArray(Charsets.UTF_8))
        return convertDERToRaw(s.sign(), rsSize).encodeBase64Url()
    }
}

public data object ES256: EcdsaBase(JWS.Id.ES256, SHAType.SHA256)
public data object ES384: EcdsaBase(JWS.Id.ES384, SHAType.SHA384)
public data object ES512: EcdsaBase(JWS.Id.ES512, SHAType.SHA512)
