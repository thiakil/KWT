

package com.thiakil.kwt

import kotlinx.serialization.*

/**
 * A JOSE Header is a JSON object containing the parameters describing the cryptographic operations and parameters
 * employed.  The JOSE (JSON Object Signing and Encryption) Header is comprised of a set of Header Parameters.
 */
public interface JOSEHeader {
    /**
     * The "typ" (type) Header Parameter is used by JWS applications to declare the
     * [media type](http://www.iana.org/assignments/media-types) of this complete JWS. This is intended for use by the
     * application when more than one kind of object could be present in an application data structure that can contain
     * a JWS; the application can use this value to disambiguate among the different kinds of objects that might be
     * present. It will typically not be used by applications when the kind of object is already known.
     * This parameter is ignored by JWS implementations; any processing of this parameter is performed by the JWS
     * application.
     */
    @SerialName("typ")
    public val type: String?

    /**
     * The "alg" (algorithm) Header Parameter identifies the cryptographic algorithm used to secure the JWS.
     * The JWS Signature value is not valid if the "alg" value does not represent a supported algorithm or if there is
     * not a key for use with that algorithm associated with the party that digitally signed or MACed the content.
     * "alg" values should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" registry
     * established by [JWA](https://tools.ietf.org/html/rfc7518) or be a value that contains a Collision-Resistant Name.
     * The "alg" value is a case-sensitive ASCII string containing a StringOrURI value. This Header Parameter MUST be
     * present and MUST be understood and processed by implementations.
     */
    @SerialName("alg")
    @Required
    public val algorithm: JWS.Id

    /**
     * The "jku" (JWK Set URL) Header Parameter is a URI (RFC3986) that refers to a resource for a set of JSON-encoded
     * public keys, one of which corresponds to the key used to digitally sign the JWS. The keys MUST be encoded as a
     * JWK Set. The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request to
     * retrieve the JWK Set MUST use Transport Layer Security (TLS); and the identity of the server MUST be validated,
     * as per Section 6 of RFC 6125.
     */
    @SerialName("jku")
    public val jwkSetUrl: String?

    /**
     * The "jwk" (JSON Web Key) Header Parameter is the public key that corresponds to the key used to digitally sign
     * the JWS. This key is represented as a JSON Web Key.
     */
    @SerialName("jwk")
    public val jsonWebKey: JsonWebKey?

    /**
     * The "kid" (key ID) Header Parameter is a hint indicating which key was used to secure the JWS.
     * This parameter allows originators to explicitly signal a change of key to recipients. The structure of the "kid"
     * value is unspecified. Its value MUST be a case-sensitive string. Use of this Header Parameter is OPTIONAL.
     *
     * When used with a JWK, the "kid" value is used to match a JWK "kid" parameter value.
     */
    @SerialName("kid")
    public val keyId: String?

    /**
     * The "x5u" (X.509 URL) Header Parameter is a URI that refers to a resource for the X.509 public key certificate or
     * certificate chain (RFC5280) corresponding to the key used to digitally sign the JWS. The identified resource MUST
     * provide a representation of the certificate or certificate chain that conforms to RFC 5280 in PEM-encoded form,
     * with each certificate delimited as specified in Section 6.1 of RFC 4945. The certificate containing the public
     * key corresponding to the key used to digitally sign the JWS MUST be the first certificate. This MAY be followed
     * by additional certificates, with each subsequent certificate being the one used to certify the previous one.
     * The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request to retrieve the
     * certificate MUST use TLS; and the identity of the server MUST be validated, as per Section 6 of RFC 6125.
     */
    @SerialName("x5u")
    public val x509Url: String?

    /**
     * The "x5c" (X.509 certificate chain) Header Parameter contains the X.509 public key certificate or certificate
     * chain (RFC5280) corresponding to the key used to digitally sign the JWS. The certificate or certificate chain is
     * represented as a JSON array of certificate value strings. Each string in the array is a base64-encoded (Section 4
     * of RFC4648 -- not base64url-encoded) DER (ITU.X690.2008) PKIX certificate value. The certificate containing the
     * public key corresponding to the key used to digitally sign the JWS MUST be the first certificate. This MAY be
     * followed by additional certificates, with each subsequent certificate being the one used to certify the previous
     * one. The recipient MUST validate the certificate chain according to RFC 5280 and consider the certificate or
     * certificate chain to be invalid if any validation failure occurs.
     */
    @SerialName("x5c")
    public val x509CertChain: List<String>?

    /**
     * The "cty" (content type) Header Parameter is used by JWS applications to declare the media type
     * ([IANA.MediaTypes](http://www.iana.org/assignments/media-types) of the secured content (the payload).
     * This is intended for use by the application when more than one kind of object could be present in the JWS
     * Payload; the application can use this value to disambiguate among the different kinds of objects that might be
     * present. It will typically not be used by applications when the kind of object is already known. This parameter
     * is ignored by JWS implementations; any processing of this parameter is performed by the JWS application.
     */
    @SerialName("cty")
    public val contentType: String?

    /**
     * The "crit" (critical) Header Parameter indicates that extensions to this specification and/or
     * [JWA](https://tools.ietf.org/html/rfc7518) are being used that MUST be understood and processed. Its value is an
     * array listing the Header Parameter names present in the JOSE Header that use those extensions. If any of the
     * listed extension Header Parameters are not understood and supported by the recipient, then the JWS is invalid.
     * Producers MUST NOT include Header Parameter names defined by the JWS specification or JWA for use with JWS,
     * duplicate names, or names that do not occur as Header Parameter names within the JOSE Header in the "crit" list.
     * Producers MUST NOT use the empty list "[]" as the "crit" value. Recipients MAY consider the JWS to be invalid if
     * the critical list contains any Header Parameter names defined by this specification or JWA for use with JWS or if
     * any other constraints on its use are violated.  When used, this Header Parameter MUST be integrity protected;
     * therefore, it MUST occur only within the JWS Protected Header. Use of this Header Parameter is OPTIONAL.
     * This Header Parameter MUST be understood and processed by implementations.
     */
    @SerialName("crit")
    public val critical: List<String>?
}
