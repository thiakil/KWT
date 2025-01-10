package com.thiakil.kwt

import com.thiakil.kwt.helpers.decodeBase64UrlBytes
import com.thiakil.kwt.helpers.decodeBase64UrlString
import com.thiakil.kwt.helpers.encodeBase64Url
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.ClassDiscriminatorMode
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

public object JWT {
    private val base64UrlFormat: Regex = Regex("[-A-Za-z0-9_]+")
    private val serialModule: SerializersModule = SerializersModule {
        //declare the interfaces as being defaulted to the data classes
        polymorphic(JWTClaimsSet::class) {
            subclass(JWTClaimsSetData::class)
            subclass(JwtBuilder::class)
            defaultDeserializer { JWTClaimsSetData.serializer() }
        }
        polymorphic(JWTClaimsSet.Address::class) {
            subclass(JWTClaimsSetData.Address::class)
            subclass(JwtBuilder.Address::class)
            defaultDeserializer { JWTClaimsSetData.Address.serializer() }
        }
        polymorphic(JOSEHeader::class) {
            subclass(JOSEHeaderData::class)
            subclass(JwtSignatureBuilder::class)
            defaultDeserializer { JOSEHeaderData.serializer() }
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    internal val json: Json = Json {
        ignoreUnknownKeys = true
        serializersModule = serialModule
        classDiscriminatorMode = ClassDiscriminatorMode.NONE
    }


    private val knownClaims: Set<String> = mutableSetOf<String>().also {
        val claimsSerialiser = JWTClaimsSetData.serializer()
        val numElements = claimsSerialiser.descriptor.elementsCount
        for (i in 0 until numElements) {
            it.add(claimsSerialiser.descriptor.getElementName(i))
        }
    }

    /**
     * Decode a JWS Compact Format encoded JWT without verifying the signature
     *
     * @throws JWSDecodeException if the token is malformed
     */
    public fun decodeUnverified(jwsToken: String): DecodedJWT {
        val parts = jwsToken.split(".")
        when {
            parts.size < 2 -> throw JWSDecodeException("Invalid JWS")
            parts.size == 5 -> throw JWSDecodeException("JWE not supported")
            parts.size > 3 -> throw JWSDecodeException("Unrecognised JWS token")
            parts.size == 3 -> if (parts[2] != "" && !parts[2].matches(base64UrlFormat)) throw JWSDecodeException("Signature bas64 invalid")
        }
        if (!parts[0].matches(base64UrlFormat)) throw JWSDecodeException("Header base64 invalid")
        if (!parts[1].matches(base64UrlFormat)) throw JWSDecodeException("Payload bas64 invalid")
        val header = try {
            json.decodeFromString<JOSEHeaderData>(parts[0].decodeBase64UrlString())
        } catch (e: Exception) {
            throw JWSDecodeException("Header deserialisation failed: ${e.message}", e)
        }
        //technically it should still have a third part, but it will be an empty string
        if (header.algorithm != JWS.Id.NONE && parts.size != 3) throw JWSDecodeException("missing signature")
        val payloadRaw = try {
            json.parseToJsonElement(parts[1].decodeBase64UrlString())
        } catch (e: Exception) {
            throw JWSDecodeException("Payload deserialisation failed: ${e.message}", e)
        }
        val payload = try {
            json.decodeFromJsonElement<JWTClaimsSetData>(payloadRaw)
        } catch (e: Exception) {
            throw JWSDecodeException("Payload deserialisation failed: ${e.message}", e)
        }
        val payloadUnknowns = payloadRaw.jsonObject.toMutableMap()
        knownClaims.forEach { payloadUnknowns.remove(it) }
        val signature = if (parts.size == 3 && parts[2] != "") parts[2].decodeBase64UrlBytes() else null
        return DecodedJWT(
            header = header,
            payload = JWTPayload(payload, payloadUnknowns),
            signature = signature?.let { UnverifiedSignature(parts[0] + "." + parts[1], it) }
        )
    }

    /**
     * Basic decode + validate method. Expiry dates must still be checked by caller
     */
    public inline fun validate(jwsToken: String, keyProvider: (JOSEHeader) -> SigningKey): JWTPayload {
        val token = decodeUnverified(jwsToken)
        val signature = token.signature
        if (token.header.algorithm == JWS.Id.NONE || signature == null) {
            throw JWSDecodeException("Can't validate token without a signature")
        }
        if (!JWS[token.header.algorithm].verify(signature, keyProvider(token.header))) {
            throw JWSDecodeException("Signature verification failed")
        }
        return token.payload
    }

    public fun validate(jwsToken: String, key: SigningKey): JWTPayload = validate(jwsToken, { key })
}

public class JWSDecodeException(message: String, cause: Exception? = null) : RuntimeException(message, cause)

public data class DecodedJWT(
    public val header: JOSEHeader,
    public val payload: JWTPayload,
    public val signature: UnverifiedSignature?
)

public data class JWTPayload(
    internal val claimsSet: JWTClaimsSet,
    public val unknownClaims: Map<String, JsonElement> = emptyMap()
) : JWTClaimsSet by claimsSet {

    private fun JOSEHeader.serialise(): String = JWT.json.encodeToString(this).encodeBase64Url()

    private fun serialise(): String {
        val payloadJson = JWT.json.encodeToString(JsonObject(getFields()))
        return payloadJson.encodeBase64Url()
    }

    internal fun getFields(): Map<String, JsonElement> {
        val fields = mutableMapOf<String, JsonElement>()
        fields.putAll(JWT.json.encodeToJsonElement(this.claimsSet).jsonObject)
        fields.putAll(JWT.json.encodeToJsonElement(this.unknownClaims).jsonObject)
        return fields
    }

    /**
     * Serialise & sign the payload with the specified algorithm and key.
     */
    public fun sign(header: JOSEHeader, algorithm: JwsAlgorithm, signingKey: SigningKey): String {
        if (header.algorithm != algorithm.jwaId) {
            throw IllegalArgumentException("Header algorithm mismatch")
        }
        val toSign = header.serialise() + "." + serialise()
        return "${toSign}." + algorithm.sign(toSign, signingKey)
    }

    /**
     * Serialise & sign the payload with the specified key. Algorithm is looked up from the header
     */
    public fun sign(header: JOSEHeader, signingKey: SigningKey): String {
        return sign(header, JWS[header.algorithm], signingKey)
    }
}

public data class UnverifiedSignature(public val subject: String, public val signature: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UnverifiedSignature) return false

        if (subject != other.subject) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = subject.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}
