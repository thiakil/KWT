package node

import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.ArrayBufferView
import org.khronos.webgl.BufferDataSource

/**
 * Exposes the JavaScript [ArrayBufferView](https://developer.mozilla.org/en/docs/Web/API/ArrayBufferView) to Kotlin
 */
public external interface ArrayBufferView : BufferDataSource {
    public val buffer: ArrayBuffer
    public val byteOffset: Int
    public val byteLength: Int
}

/**
 * Exposes the JavaScript [Uint8Array](https://developer.mozilla.org/en/docs/Web/API/Uint8Array) to Kotlin
 */
public open external class Uint8Array : ArrayBufferView {
    public constructor(length: Int)
    public constructor(array: Uint8Array)
    public constructor(array: Array<Byte>)
    public constructor(buffer: ArrayBuffer, byteOffset: Int = definedExternally, length: Int = definedExternally)
    public open val length: Int
    override val buffer: ArrayBuffer
    override val byteOffset: Int
    override val byteLength: Int
    public fun set(array: Uint8Array, offset: Int = definedExternally)
    public fun set(array: Array<Byte>, offset: Int = definedExternally)
    public fun subarray(start: Int, end: Int): Uint8Array

    public companion object {
        public val BYTES_PER_ELEMENT: Int
    }
}

/**
 * Exposes the JavaScript [Int8Array](https://developer.mozilla.org/en/docs/Web/API/Int8Array) to Kotlin
 */
public external open class Int8Array : ArrayBufferView {
    public constructor(length: Int)
    public constructor(array: Int8Array)
    public constructor(array: Array<Byte>)
    public constructor(buffer: ArrayBuffer, byteOffset: Int = definedExternally, length: Int = definedExternally)
    public open val length: Int
    override val buffer: ArrayBuffer
    override val byteOffset: Int
    override val byteLength: Int
    public fun set(array: Int8Array, offset: Int = definedExternally)
    public fun set(array: Array<Byte>, offset: Int = definedExternally)
    public fun subarray(start: Int, end: Int): Int8Array

    public companion object {
        public val BYTES_PER_ELEMENT: Int
    }
}

public external class Buffer : Uint8Array {
    public fun equals(otherBuffer: Buffer): Boolean
    public fun compare(otherBuffer: Buffer): Int
}

//https://slack-chats.kotlinlang.org/t/14142949/ok-so-the-correct-way-to-transform-a-bytearray-int8array-to-
public inline fun Uint8Array.toKotlinArray(): ByteArray =
    Int8Array(buffer, byteOffset, byteLength).unsafeCast<ByteArray>()

@Suppress("NOTHING_TO_INLINE")
public inline fun ByteArray.toPlatformArray(): Uint8Array {
    val i8a = unsafeCast<Int8Array>()
    return Uint8Array(i8a.buffer, i8a.byteOffset, i8a.byteLength)
}