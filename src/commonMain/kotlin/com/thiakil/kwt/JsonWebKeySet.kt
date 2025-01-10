package com.thiakil.kwt

import kotlinx.serialization.Serializable

@Serializable
public data class JsonWebKeySet(public val keys: List<JsonWebKey>) : List<JsonWebKey> by keys {
    public fun serialize(): String = JsonWebKey.format.encodeToString(this)

    public companion object {
        public fun deserialize(jwkSet: String): JsonWebKeySet = JsonWebKey.format.decodeFromString(jwkSet)
    }
}
