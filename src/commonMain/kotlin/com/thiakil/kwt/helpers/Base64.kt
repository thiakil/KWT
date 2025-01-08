@file:OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)

package com.thiakil.kwt.helpers

import kotlin.io.encoding.Base64

private val base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

internal fun String.decodeBase64UrlString(): String {
    return base64.decode(this).decodeToString()
}

internal fun String.decodeBase64UrlBytes(): ByteArray {
    return base64.decode(this)
}

internal fun String.encodeBase64Url(): String {
    return base64.encode(this.toByteArray(Charsets.UTF_8))
}

internal fun ByteArray.encodeBase64Url(): String {
    return base64.encode(this)
}