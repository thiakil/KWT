

package com.thiakil.kwt

import kotlinx.serialization.*

/**
 * Data class impl of [JOSEHeader]
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
public data class JOSEHeaderData(
    @SerialName("typ")
    @EncodeDefault
    override val type: String? = "JWT",

    @SerialName("alg")
    @Required
    override val algorithm: JWS.Id,

    @SerialName("jku")
    override val jwkSetUrl: String? = null,

    @SerialName("jwk")
    override val jsonWebKey: JsonWebKey? = null,

    @SerialName("kid")
    override val keyId: String? = null,

    @SerialName("x5u")
    override val x509Url: String? = null,

    @SerialName("x5c")
    override val x509CertChain: List<String>? = null,

    @SerialName("cty")
    override val contentType: String? = null,

    @SerialName("crit")
    override val critical: List<String>? = null
) : JOSEHeader
