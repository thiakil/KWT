package com.thiakil.kwt

import com.thiakil.kwt.algorithms.UnsignedAlg
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * RFC 7518 - 3.1.  "alg" (Algorithm) Header Parameter Values for JWS
 *
 * The table below is the set of "alg" (algorithm) Header Parameter
 * values defined by this specification for use with JWS, each of which
 * is explained in more detail in the following sections:
 *
 * +--------------+-------------------------------+--------------------+
 * | "alg" Param  | Digital Signature or MAC      | Implementation     |
 * | Value        | Algorithm                     | Requirements       |
 * +--------------+-------------------------------+--------------------+
 * | HS256        | HMAC using SHA-256            | Required           |
 * | HS384        | HMAC using SHA-384            | Optional           |
 * | HS512        | HMAC using SHA-512            | Optional           |
 * | RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
 * |              | SHA-256                       |                    |
 * | RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
 * |              | SHA-384                       |                    |
 * | RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
 * |              | SHA-512                       |                    |
 * | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
 * | ES384        | ECDSA using P-384 and SHA-384 | Optional           |
 * | ES512        | ECDSA using P-521 and SHA-512 | Optional           |
 * | PS256        | RSASSA-PSS using SHA-256 and  | Optional           |
 * |              | MGF1 with SHA-256             |                    |
 * | PS384        | RSASSA-PSS using SHA-384 and  | Optional           |
 * |              | MGF1 with SHA-384             |                    |
 * | PS512        | RSASSA-PSS using SHA-512 and  | Optional           |
 * |              | MGF1 with SHA-512             |                    |
 * | none         | No digital signature or MAC   | Optional           |
 * |              | performed                     |                    |
 * +--------------+-------------------------------+--------------------+
 *
 * The use of "+" in the Implementation Requirements column indicates
 * that the requirement strength is likely to be increased in a future
 * version of the specification.
 */
public object JWS {
    @Serializable
    public enum class Id {
        HS256,
        HS384,
        HS512,
        RS256,
        RS384,
        RS512,
        ES256,
        ES384,
        ES512,
        PS256,
        PS384,
        PS512,
        @SerialName("none")
        NONE
    }
    /**
     * Check if this platform supports this algorithm for signing and verifying
     */
    public fun supports(algorithm: Id): Boolean {
        return when(algorithm) {
            Id.NONE -> true
            else -> JWS_ALGORITHMS.containsKey(algorithm)
        }
    }

    public operator fun get(algorithm: Id): JwsAlgorithm {
        return when(algorithm) {
            Id.NONE -> UnsignedAlg
            else -> JWS_ALGORITHMS[algorithm] ?: throw UnsupportedJWSAlgorithm(algorithm)
        }
    }

}

internal expect val JWS_ALGORITHMS: Map<JWS.Id, JwsAlgorithm>

public interface JwsAlgorithm {
    /** The algorithm identifier for the JOSE header */
    public val jwaId: JWS.Id

    /**
     * Verify the signature with the provided key
     * @return true when signature is valid
     */
    public fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean

    /**
     * Sign the payload, returning the Base64-URL encoded signature part
     */
    public fun sign(payload: String, key: SigningKey): String
}

/**
 * Marker interface for a crypto key which can be used for signing/signature-verification.
 * Either a deserialized JWK or a platform dependant native key.
 */
public interface SigningKey {
    /** for use with [JWS.Id.NONE] or as a default value */
    public data object NONE: SigningKey
}

public sealed class JwsException(override val message: String, cause: Exception?=null): RuntimeException(message, cause)

/** Thrown by a [JwsAlgorithm] when the key supplied cannot be used by the algorithm. */
public class UnsupportedKeyException(message: String, cause: Exception? = null): JwsException(message, cause)

/** Thrown when a signature doesn't match the algorithm's expected format */
public class InvalidSignatureException(message: String, cause: Exception? = null): JwsException(message, cause)

/** Thrown when the requested algorithm is not supported by the current platform */
public class UnsupportedJWSAlgorithm(algorithm: JWS.Id): JwsException("Unsupported algorithm: $algorithm")
