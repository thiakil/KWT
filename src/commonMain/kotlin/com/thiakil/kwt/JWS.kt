package com.thiakil.kwt

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
    /**
     * Check if this platform supports this algorithm for signing and verifying
     */
    public fun supports(algorithm: String): Boolean {
        return when(algorithm) {
            "none" -> true
            else -> JWS_ALGORITHMS.containsKey(algorithm)
        }
    }

    /**
     * Verify the signature of a JWT using JWS
     * @param jwt the decoded JWT from [JWT.decode]
     * @param signingKey the expected signing key, use [DecodedJWT.header] members for hints if needed
     * @param noneIsValid whether to accept a token without a signature
     *
     * @throws UnsupportedJWAlgorithm When an algorithm is unknown or isn't supported by the underlying platform
     * @throws UnsupportedKeyException When a key is malformed or not applicable to the alorithm
     * @throws InvalidSignatureException When a signature is malformed or otherwise invalid
     */
    public fun verify(jwt: DecodedJWT, signingKey: SigningKey, noneIsValid: Boolean = true): Boolean {
        val algorithm = jwt.header.algorithm
        if (algorithm == "none") {
            return noneIsValid && (jwt.signature == null || jwt.signature.signature.isEmpty())
        }
        if (jwt.signature == null) {
            return false
        }
        val verifier = JWS_ALGORITHMS[algorithm] ?: throw UnsupportedJWAlgorithm(algorithm)
        return verifier.verify(jwt.signature, signingKey)
    }

    public fun sign(payload: JWTPayload, algorithm: JwsAlgorithm, signingKey: SigningKey, keyId: String? = null): String {
        val header = JOSEHeaderData(
            type = "jwt",
            algorithm = algorithm.jwaId,
            keyId = keyId
        )
        val toSign = payload.serialise(header)
        return "${toSign}." + algorithm.sign(toSign, signingKey)
    }
}

internal expect val JWS_ALGORITHMS: Map<String, JwsAlgorithm>

public sealed class JwsException(override val message: String, cause: Exception?=null): Exception(message, cause)

public class UnsupportedJWAlgorithm(algorithm: String): JwsException("Unsupported algorithm: $algorithm")

public interface JwsAlgorithm {
    public val jwaId: String
    public fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean
    public fun sign(payload: String, key: SigningKey): String
}

/**
 * Marker interface for a crypto key which can be used for signing/signature-verification.
 * Either a deserialized JWK or a platform dependant native key.
 */
public interface SigningKey

/**
 * Thrown by a [JwsAlgorithm] when the key supplied cannot by used by the algorithm.
 */
public class UnsupportedKeyException(message: String, cause: Exception? = null): JwsException(message, cause)

/** Thrown when a signature doesn't match the algorithm's expected format */
public class InvalidSignatureException(message: String, cause: Exception? = null): JwsException(message, cause)