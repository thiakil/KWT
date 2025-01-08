

package com.thiakil.kwt

import kotlinx.serialization.*

@Serializable
public class JsonWebKeySet(public val keys: List<JsonWebKey>): List<JsonWebKey> by keys {

    public companion object {
        public fun decodeFromString(jwkSet: String): JsonWebKeySet = JsonWebKey.format.decodeFromString(jwkSet)
    }
}
