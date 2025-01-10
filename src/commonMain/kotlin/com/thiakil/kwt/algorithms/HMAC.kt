package com.thiakil.kwt.algorithms

import com.thiakil.kwt.SigningKey
import io.ktor.utils.io.charsets.*
import io.ktor.utils.io.core.*

public interface HmacKey: SigningKey {
    public val secretBytes: ByteArray
}

public class HmacByteKey(override val secretBytes: ByteArray): HmacKey

public data class HmacStringKey(val secret: String): HmacKey {
    override val secretBytes: ByteArray
        get() = secret.toByteArray(Charsets.UTF_8)
}