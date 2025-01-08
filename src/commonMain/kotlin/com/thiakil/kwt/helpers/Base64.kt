@file:OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)

package com.thiakil.kwt.helpers

import kotlin.io.encoding.Base64

private val base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

fun String.decodeBase64UrlString(): String {
    return base64.decode(this).decodeToString()
}

fun String.decodeBase64UrlBytes(): ByteArray {
    return base64.decode(this)
}

fun String.encodeBase64Url(): String {
    return base64.encode(this.toByteArray(Charsets.UTF_8))
}

fun ByteArray.encodeBase64Url(): String {
    return base64.encode(this)
}