package com.thiakil.kwt

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.ClassDiscriminatorMode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.modules.SerializersModule

@OptIn(ExperimentalSerializationApi::class)
@Serializable
public sealed class JsonWebKey: SigningKey {
    /**
     * The "kty" (key type) parameter identifies the cryptographic algorithm
     * family used with the key, such as "RSA" or "EC".  "kty" values should
     * either be registered in the IANA "JSON Web Key Types" registry
     * established by [JWS] or be a value that contains a Collision-
     * Resistant Name.  The "kty" value is a case-sensitive string.  This
     * member MUST be present in a JWK.
     *
     * A list of defined "kty" values can be found in the IANA "JSON Web Key
     * Types" registry established by [JWS]; the initial contents of this
     * registry are the values defined in Section 6.1 of [JWS].
     *
     * The key type definitions include specification of the members to be
     * used for those key types.  Members used with specific "kty" values
     * can be found in the IANA "JSON Web Key Parameters" registry
     */
    @SerialName("kty")
    @EncodeDefault
    public abstract val keyType: String

    /**
     * The "use" (public key use) parameter identifies the intended use of
     * the public key.  The "use" parameter is employed to indicate whether
     * a public key is used for encrypting data or verifying the signature
     * on data.
     *
     * Values defined by this specification are:
     *
     * o  "sig" (signature)
     * o  "enc" (encryption)
     *
     * Other values MAY be used.  The "use" value is a case-sensitive
     * string.  Use of the "use" member is OPTIONAL, unless the application
     * requires its presence.
     *
     * When a key is used to wrap another key and a public key use
     * designation for the first key is desired, the "enc" (encryption) key
     * use value is used, since key wrapping is a kind of encryption.  The
     * "enc" value is also to be used for public keys used for key agreement
     * operations.
     *
     * Additional "use" (public key use) values can be registered in the
     * IANA "JSON Web Key Use" registry established by Section 8.2.
     * Registering any extension values used is highly recommended when this
     * specification is used in open environments, in which multiple
     * organizations need to have a common understanding of any extensions
     * used.  However, unregistered extension values can be used in closed
     * environments, in which the producing and consuming organization will
     * always be the same.
     */
    @SerialName("use")
    public abstract val use: String?

    /**
     * The "key_ops" (key operations) parameter identifies the operation(s)
     * for which the key is intended to be used.  The "key_ops" parameter is
     * intended for use cases in which public, private, or symmetric keys
     * may be present.
     *
     * Its value is an array of key operation values.  Values defined by
     * this specification are:
     *
     * o  "sign" (compute digital signature or MAC)
     * o  "verify" (verify digital signature or MAC)
     * o  "encrypt" (encrypt content)
     * o  "decrypt" (decrypt content and validate decryption, if applicable)
     * o  "wrapKey" (encrypt key)
     * o  "unwrapKey" (decrypt key and validate decryption, if applicable)
     * o  "deriveKey" (derive key)
     * o  "deriveBits" (derive bits not to be used as a key)
     *
     * (Note that the "key_ops" values intentionally match the "KeyUsage"
     * values defined in the Web Cryptography API
     * [W3C.CR-WebCryptoAPI-20141211] specification.)
     *
     * Other values MAY be used.  The key operation values are case-
     * sensitive strings.  Duplicate key operation values MUST NOT be
     * present in the array.  Use of the "key_ops" member is OPTIONAL,
     * unless the application requires its presence.
     *
     * Multiple unrelated key operations SHOULD NOT be specified for a key
     * because of the potential vulnerabilities associated with using the
     * same key with multiple algorithms.  Thus, the combinations "sign"
     * with "verify", "encrypt" with "decrypt", and "wrapKey" with
     * "unwrapKey" are permitted, but other combinations SHOULD NOT be used.
     *
     * Additional "key_ops" (key operations) values can be registered in the
     * IANA "JSON Web Key Operations" registry established by Section 8.3.
     * The same considerations about registering extension values apply to
     * the "key_ops" member as do for the "use" member.
     *
     * The "use" and "key_ops" JWK members SHOULD NOT be used together;
     * however, if both are used, the information they convey MUST be
     * consistent.  Applications should specify which of these members they
     * use, if either is to be used by the application.
     */
    @SerialName("key_ops")
    public abstract val keyOperations: Set<String>?

    /**
     * The "alg" (algorithm) parameter identifies the algorithm intended for
     * use with the key.  The values used should either be registered in the
     * IANA "JSON Web Signature and Encryption Algorithms" registry
     * established by [JWS] or be a value that contains a Collision-
     * Resistant Name.  The "alg" value is a case-sensitive ASCII string.
     * Use of this member is OPTIONAL.
     */
    @SerialName("alg")
    public abstract val algorithm: String?

    /**
     * The "kid" (key ID) parameter is used to match a specific key.  This
     * is used, for instance, to choose among a set of keys within a JWK Set
     * during key rollover.  The structure of the "kid" value is
     * unspecified.  When "kid" values are used within a JWK Set, different
     * keys within the JWK Set SHOULD use distinct "kid" values.  (One
     * example in which different keys might use the same "kid" value is if
     * they have different "kty" (key type) values but are considered to be
     * equivalent alternatives by the application using them.)  The "kid"
     * value is a case-sensitive string.  Use of this member is OPTIONAL.
     * When used with JWS or JWE, the "kid" value is used to match a JWS or
     * JWE "kid" Header Parameter value.
     */
    @SerialName("kid")
    public abstract val keyId: String?

    /**
     * The "x5u" (X.509 URL) parameter is a URI RFC 3986 that refers to a
     * resource for an X.509 public key certificate or certificate chain
     * RFC 5280.  The identified resource MUST provide a representation of
     * the certificate or certificate chain that conforms to RFC 5280
     * RFC 5280 in PEM-encoded form, with each certificate delimited as
     * specified in Section 6.1 of RFC 4945.  The key in the first
     * certificate MUST match the public key represented by other members of
     * the JWK.  The protocol used to acquire the resource MUST provide
     * integrity protection; an HTTP GET request to retrieve the certificate
     * MUST use TLS RFC 2818, RFC 5246; the identity of the server MUST be
     * validated, as per Section 6 of RFC 6125.  Use of this
     * member is OPTIONAL.
     *
     * While there is no requirement that optional JWK members providing key
     * usage, algorithm, or other information be present when the "x5u"
     * member is used, doing so may improve interoperability for
     * applications that do not handle PKIX certificates RFC 5280.  If
     * other members are present, the contents of those members MUST be
     * semantically consistent with the related fields in the first
     * certificate.  For instance, if the "use" member is present, then it
     * MUST correspond to the usage that is specified in the certificate,
     * when it includes this information.  Similarly, if the "alg" member is
     * present, it MUST correspond to the algorithm specified in the
     * certificate.
     */
    @SerialName("x5u")
    public abstract val x509Url: String?

    /**
     * The "x5c" (X.509 certificate chain) parameter contains a chain of one
     * or more PKIX certificates RFC 5280.  The certificate chain is
     * represented as a JSON array of certificate value strings.  Each
     * string in the array is a base64-encoded (Section 4 of RFC 4648 --
     * not base64url-encoded) DER (ITU.X690.1994) PKIX certificate value.
     * The PKIX certificate containing the key value MUST be the first
     * certificate.  This MAY be followed by additional certificates, with
     * each subsequent certificate being the one used to certify the
     * previous one.  The key in the first certificate MUST match the public
     * key represented by other members of the JWK.  Use of this member is
     * OPTIONAL.
     *
     * As with the "x5u" member, optional JWK members providing key usage,
     * algorithm, or other information MAY also be present when the "x5c"
     * member is used.  If other members are present, the contents of those
     * members MUST be semantically consistent with the related fields in
     * the first certificate.  See the last paragraph of Section 4.6 for
     * additional guidance on this.
     */
    @SerialName("x5c")
    public abstract val x509CertificateChain: List<String>?

    /**
     * The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a
     * base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
     * encoding of an X.509 certificate RFC 5280.  Note that certificate
     * thumbprints are also sometimes known as certificate fingerprints.
     * The key in the certificate MUST match the public key represented by
     * other members of the JWK.  Use of this member is OPTIONAL.
     *
     * As with the "x5u" member, optional JWK members providing key usage,
     * algorithm, or other information MAY also be present when the "x5t"
     * member is used.  If other members are present, the contents of those
     * members MUST be semantically consistent with the related fields in
     * the referenced certificate.  See the last paragraph of Section 4.6
     * for additional guidance on this.
     */
    @SerialName("x5t")
    public abstract val x509CertificateSha1Thumbprint: String?

    /**
     * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) parameter is a
     * base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER
     * encoding of an X.509 certificate RFC 5280.  Note that certificate
     * thumbprints are also sometimes known as certificate fingerprints.
     * The key in the certificate MUST match the public key represented by
     * other members of the JWK.  Use of this member is OPTIONAL.
     *
     * As with the "x5u" member, optional JWK members providing key usage,
     * algorithm, or other information MAY also be present when the
     * "x5t#S256" member is used.  If other members are present, the
     * contents of those members MUST be semantically consistent with the
     * related fields in the referenced certificate.
     */
    @SerialName("x5t#S256")
    public abstract val x509CertificateSha256Thumbprint: String?

    @Serializable
    @SerialName("EC")
    public data class EllipticCurve(
        @SerialName("use") override val use: String? = null,
        @SerialName("key_ops") override val keyOperations: Set<String>? = null,
        @SerialName("alg") override val algorithm: String? = null,
        @SerialName("kid") override val keyId: String? = null,
        @SerialName("x5u") override val x509Url: String? = null,
        @SerialName("x5c") override val x509CertificateChain: List<String>? = null,
        @SerialName("x5t") override val x509CertificateSha1Thumbprint: String? = null,
        @SerialName("x5t#S256") override val x509CertificateSha256Thumbprint: String? = null,

        /**
         * The "crv" (curve) parameter identifies the cryptographic curve used
         * with the key.  Curve values from DSS used by this specification
         * are:
         *
         * o  "P-256"
         * o  "P-384"
         * o  "P-521"
         *
         * These values are registered in the IANA "JSON Web Key Elliptic Curve"
         * registry defined in Section 7.6. Additional "crv" values can be
         * registered by other specifications. Specifications registering
         * additional curves must define what parameters are used to represent
         * keys for the curves registered. The "crv" value is a case-sensitive
         * string.
         *
         * SEC1 point compression is not supported for any of these three
         * curves.
         */
        @SerialName("crv")
        public val curve: String,

        /**
         * The "x" (x coordinate) parameter contains the x coordinate for the
         * Elliptic Curve point. It is represented as the base64url encoding of
         * the octet string representation of the coordinate, as defined in
         * Section 2.3.5 of SEC1. The length of this octet string MUST
         * be the full size of a coordinate for the curve specified in the "crv"
         * parameter. For example, if the value of "crv" is "P-521", the octet
         * string must be 66 octets long.
         */
        @SerialName("x")
        @Serializable(with= Base64UrlBinary::class)
        public val x: ByteArray,

        /**
         * The "y" (y coordinate) parameter contains the y coordinate for the
         * Elliptic Curve point. It is represented as the base64url encoding of
         * the octet string representation of the coordinate, as defined in
         * Section 2.3.5 of SEC1. The length of this octet string MUST
         * be the full size of a coordinate for the curve specified in the "crv"
         * parameter. For example, if the value of "crv" is "P-521", the octet
         * string must be 66 octets long.
         */
        @SerialName("y")
        @Serializable(with= Base64UrlBinary::class)
        public val y: ByteArray,

        /**
         * The "d" (ECC private key) parameter contains the Elliptic Curve
         * private key value. It is represented as the base64url encoding of
         * the octet string representation of the private key value, as defined
         * in Section 2.3.7 of SEC1. The length of this octet string
         * MUST be ceiling(log-base-2(n)/8) octets (where n is the order of the
         * curve).
         */
        @SerialName("d")
        @Serializable(with = Base64UrlBinary::class)
        public val eccPrivateKey: ByteArray? = null,
    ): JsonWebKey() {
        @SerialName("kty")
        @EncodeDefault
        override val keyType: String = "EC"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is EllipticCurve) return false

            if (!super.equals(other)) return false
            if (curve != other.curve) return false
            if (!x.contentEquals(other.x)) return false
            if (!y.contentEquals(other.y)) return false
            if (eccPrivateKey != null) {
                if (other.eccPrivateKey == null) return false
                if (!eccPrivateKey.contentEquals(other.eccPrivateKey)) return false
            } else if (other.eccPrivateKey != null) return false

            return true
        }

        override fun hashCode(): Int {
            var result = super.hashCode()
            result = 31 * result + curve.hashCode()
            result = 31 * result + x.contentHashCode()
            result = 31 * result + y.contentHashCode()
            result = 31 * result + (eccPrivateKey?.contentHashCode() ?: 0)
            return result
        }
    }

    @Serializable
    public data class RSA(
        @SerialName("use") override val use: String? = null,
        @SerialName("key_ops") override val keyOperations: Set<String>? = null,
        @SerialName("alg") override val algorithm: String? = null,
        @SerialName("kid") override val keyId: String? = null,
        @SerialName("x5u") override val x509Url: String? = null,
        @SerialName("x5c") override val x509CertificateChain: List<String>? = null,
        @SerialName("x5t") override val x509CertificateSha1Thumbprint: String? = null,
        @SerialName("x5t#S256") override val x509CertificateSha256Thumbprint: String? = null,

        //region RSA Public keys
        /**
         * The "n" (modulus) parameter contains the modulus value for the RSA
         * public key.  It is represented as a Base64urlUInt-encoded value.
         *
         * Note that implementers have found that some cryptographic libraries
         * prefix an extra zero-valued octet to the modulus representations they
         * return, for instance, returning 257 octets for a 2048-bit key, rather
         * than 256.  Implementations using such libraries will need to take
         * care to omit the extra octet from the base64url-encoded
         * representation.
         */
        @SerialName("n")
        @Serializable(with = Base64UrlBinary::class)
        public val modulus: ByteArray? = null,

        /**
         * The "e" (exponent) parameter contains the exponent value for the RSA
         * public key.  It is represented as a Base64urlUInt-encoded value.
         *
         * For instance, when representing the value 65537, the octet sequence
         * to be base64url-encoded MUST consist of the three octets [1, 0, 1];
         * the resulting representation for this value is "AQAB".
         */
        @SerialName("e")
        @Serializable(with = Base64UrlBinary::class)
        public val exponent: ByteArray? = null,
        //endregion

        //region RSA Private Keys
        /**
         * The "d" (private exponent) parameter contains the private exponent
         * value for the RSA private key.  It is represented as a Base64urlUInt-
         * encoded value.
         *
         * The parameter "d" is REQUIRED for RSA private keys.  The others enable
         * optimizations and SHOULD be included by producers of JWKs
         * representing RSA private keys.  If the producer includes any of the
         * other private key parameters, then all of the others MUST be present,
         * with the exception of "oth", which MUST only be present when more
         * than two prime factors were used.
         */
        @SerialName("d")
        @Serializable(with = Base64UrlBinary::class)
        public val privateExponent: ByteArray? = null,

        /**
         * The "p" (first prime factor) parameter contains the first prime
         * factor.  It is represented as a Base64urlUInt-encoded value.
         */
        @SerialName("p")
        @Serializable(with = Base64UrlBinary::class)
        public val firstPrimeFactor: ByteArray? = null,

        /**
         * The "q" (second prime factor) parameter contains the second prime
         * factor.  It is represented as a Base64urlUInt-encoded value.
         */
        @SerialName("q")
        @Serializable(with = Base64UrlBinary::class)
        public val secondPrimeFactor: ByteArray? = null,

        /**
         * The "dp" (first factor CRT exponent) parameter contains the Chinese
         * Remainder Theorem (CRT) exponent of the first factor.  It is
         * represented as a Base64urlUInt-encoded value.
         */
        @SerialName("dp")
        @Serializable(with = Base64UrlBinary::class)
        public val firstFactorCRTExponent: ByteArray? = null,

        /**
         * The "dq" (second factor CRT exponent) parameter contains the CRT
         * exponent of the second factor.  It is represented as a Base64urlUInt-
         * encoded value.
         */
        @SerialName("dq")
        @Serializable(with = Base64UrlBinary::class)
        public val secondFactorCRTExponent: ByteArray? = null,

        /**
         * The "qi" (first CRT coefficient) parameter contains the CRT
         * coefficient of the second factor.  It is represented as a
         * Base64urlUInt-encoded value.
         */
        @SerialName("qi")
        @Serializable(with = Base64UrlBinary::class)
        public val firstCRTCoefficient: ByteArray? = null,

        /**
         * The "oth" (other primes info) parameter contains an array of
         * information about any third and subsequent primes, should they exist.
         * When only two primes have been used (the normal case), this parameter
         * MUST be omitted.  When three or more primes have been used, the
         * number of array elements MUST be the number of primes used minus two.
         * For more information on this case, see the description of the
         * OtherPrimeInfo parameters in Appendix A.1.2 of RFC 3447,
         * upon which the following parameters are modeled.  If the consumer of
         * a JWK does not support private keys with more than two primes and it
         * encounters a private key that includes the "oth" parameter, then it
         * MUST NOT use the key.
         */
        @SerialName("oth")
        public val otherPrimesInfo: List<OtherPrimeInfo>? = null,
    ): JsonWebKey() {

        @SerialName("kty")
        @EncodeDefault
        override val keyType: String = "RSA"

        @Serializable
        public data class OtherPrimeInfo (
            /**
             * The "r" (prime factor) parameter within an "oth" array member
             * represents the value of a subsequent prime factor.  It is represented
             * as a Base64urlUInt-encoded value.
             */
            @SerialName("r")
            @Serializable(with = Base64UrlBinary::class)
            public val primeFactor: ByteArray,

            /**
             * The "d" (factor CRT exponent) parameter within an "oth" array member
             * represents the CRT exponent of the corresponding prime factor.  It is
             * represented as a Base64urlUInt-encoded value.
             */
            @SerialName("d")
            @Serializable(with = Base64UrlBinary::class)
            public val factorCRTExponent: ByteArray,

            /**
             * The "t" (factor CRT coefficient) parameter within an "oth" array
             * member represents the CRT coefficient of the corresponding prime
             * factor.  It is represented as a Base64urlUInt-encoded value.
             */
            @SerialName("t")
            @Serializable(with = Base64UrlBinary::class)
            public val factorCRTCoefficient: ByteArray,
        ) {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is OtherPrimeInfo) return false

                if (!primeFactor.contentEquals(other.primeFactor)) return false
                if (!factorCRTExponent.contentEquals(other.factorCRTExponent)) return false
                if (!factorCRTCoefficient.contentEquals(other.factorCRTCoefficient)) return false

                return true
            }

            override fun hashCode(): Int {
                var result = primeFactor.contentHashCode()
                result = 31 * result + factorCRTExponent.contentHashCode()
                result = 31 * result + factorCRTCoefficient.contentHashCode()
                return result
            }
        }
        //endregion

        public val isValidPublicKey: Boolean get() = modulus != null && exponent != null
        public val isValidPrivateKey: Boolean get() = isValidPublicKey && privateExponent != null

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RSA) return false
            if (!super.equals(other)) return false

            if (modulus != null) {
                if (other.modulus == null) return false
                if (!modulus.contentEquals(other.modulus)) return false
            } else if (other.modulus != null) return false
            if (exponent != null) {
                if (other.exponent == null) return false
                if (!exponent.contentEquals(other.exponent)) return false
            } else if (other.exponent != null) return false
            if (privateExponent != null) {
                if (other.privateExponent == null) return false
                if (!privateExponent.contentEquals(other.privateExponent)) return false
            } else if (other.privateExponent != null) return false
            if (firstPrimeFactor != null) {
                if (other.firstPrimeFactor == null) return false
                if (!firstPrimeFactor.contentEquals(other.firstPrimeFactor)) return false
            } else if (other.firstPrimeFactor != null) return false
            if (secondPrimeFactor != null) {
                if (other.secondPrimeFactor == null) return false
                if (!secondPrimeFactor.contentEquals(other.secondPrimeFactor)) return false
            } else if (other.secondPrimeFactor != null) return false
            if (firstFactorCRTExponent != null) {
                if (other.firstFactorCRTExponent == null) return false
                if (!firstFactorCRTExponent.contentEquals(other.firstFactorCRTExponent)) return false
            } else if (other.firstFactorCRTExponent != null) return false
            if (secondFactorCRTExponent != null) {
                if (other.secondFactorCRTExponent == null) return false
                if (!secondFactorCRTExponent.contentEquals(other.secondFactorCRTExponent)) return false
            } else if (other.secondFactorCRTExponent != null) return false
            if (firstCRTCoefficient != null) {
                if (other.firstCRTCoefficient == null) return false
                if (!firstCRTCoefficient.contentEquals(other.firstCRTCoefficient)) return false
            } else if (other.firstCRTCoefficient != null) return false
            if (otherPrimesInfo != other.otherPrimesInfo) return false

            return true
        }

        override fun hashCode(): Int {
            var result = super.hashCode()
            result = 31 * result + (modulus?.contentHashCode() ?: 0)
            result = 31 * result + (exponent?.contentHashCode() ?: 0)
            result = 31 * result + (privateExponent?.contentHashCode() ?: 0)
            result = 31 * result + (firstPrimeFactor?.contentHashCode() ?: 0)
            result = 31 * result + (secondPrimeFactor?.contentHashCode() ?: 0)
            result = 31 * result + (firstFactorCRTExponent?.contentHashCode() ?: 0)
            result = 31 * result + (secondFactorCRTExponent?.contentHashCode() ?: 0)
            result = 31 * result + (firstCRTCoefficient?.contentHashCode() ?: 0)
            result = 31 * result + (otherPrimesInfo?.hashCode() ?: 0)
            return result
        }
    }

    @Serializable
    public data class Symmetric (
        @SerialName("use") override val use: String? = null,
        @SerialName("key_ops") override val keyOperations: Set<String>? = null,
        @SerialName("alg") override val algorithm: String? = null,
        @SerialName("kid") override val keyId: String? = null,
        @SerialName("x5u") override val x509Url: String? = null,
        @SerialName("x5c") override val x509CertificateChain: List<String>? = null,
        @SerialName("x5t") override val x509CertificateSha1Thumbprint: String? = null,
        @SerialName("x5t#S256") override val x509CertificateSha256Thumbprint: String? = null,

        /**
         * The "k" (key value) parameter contains the value of the symmetric (or
         * other single-valued) key. It is represented as the base64url
         * encoding of the octet sequence containing the key value.
         */
        @SerialName("k")
        @Serializable(with = Base64UrlBinary::class)
        public val keyValue: ByteArray
    ): JsonWebKey() {
        @SerialName("kty")
        @EncodeDefault
        override val keyType: String = "oct"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Symmetric) return false

            if (!super.equals(other)) return false
            if (!keyValue.contentEquals(other.keyValue)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = super.hashCode()
            result = 31 * result + keyValue.contentHashCode()
            return result
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JsonWebKey) return false

        if (use != other.use) return false
        if (keyOperations != other.keyOperations) return false
        if (algorithm != other.algorithm) return false
        if (keyId != other.keyId) return false
        if (x509Url != other.x509Url) return false
        if (x509CertificateChain != other.x509CertificateChain) return false
        if (x509CertificateSha1Thumbprint != other.x509CertificateSha1Thumbprint) return false
        if (x509CertificateSha256Thumbprint != other.x509CertificateSha256Thumbprint) return false

        return true
    }

    override fun hashCode(): Int {
        var result = use?.hashCode() ?: 0
        result = 31 * result + (keyOperations?.hashCode() ?: 0)
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (keyId?.hashCode() ?: 0)
        result = 31 * result + (x509Url?.hashCode() ?: 0)
        result = 31 * result + (x509CertificateChain?.hashCode() ?: 0)
        result = 31 * result + (x509CertificateSha1Thumbprint?.hashCode() ?: 0)
        result = 31 * result + (x509CertificateSha256Thumbprint?.hashCode() ?: 0)
        return result
    }

    public companion object {
        public val serializers: SerializersModule = SerializersModule {
            polymorphicDefaultDeserializer(JsonWebKey::class, { KeyPolymorphicSerializer })
        }

        /**
         * Use this to deserialize JWKs, using the Key Type field to determine which class to use
         */
        internal val format: Json = Json {
            serializersModule = serializers
            ignoreUnknownKeys = true
            classDiscriminatorMode = ClassDiscriminatorMode.NONE
            classDiscriminator = "_____unused"
        }
    }

    internal object KeyPolymorphicSerializer: JsonContentPolymorphicSerializer<JsonWebKey>(JsonWebKey::class) {
        override fun selectDeserializer(element: JsonElement): DeserializationStrategy<JsonWebKey> {
            return when (val keyType = element.jsonObject["kty"]?.jsonPrimitive?.content) {
                "RSA" -> RSA.serializer()
                "EC" -> EllipticCurve.serializer()
                "oct" -> Symmetric.serializer()
                else -> throw SerializationException("Unknown key type: $keyType")
            }
        }
    }
}
