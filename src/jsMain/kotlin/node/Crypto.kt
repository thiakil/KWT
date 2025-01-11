package node

import com.thiakil.kwt.JsonWebKey
import com.thiakil.kwt.JsonWebKeySet
import com.thiakil.kwt.SigningKey

@JsModule("node:crypto")
public external object Crypto {
    public fun createHmac(algorithm: String, key: String): Hmac
    public fun createHmac(algorithm: String, key: Uint8Array): Hmac
    public fun createSign(algorithm: String):Sign
    public fun createVerify(algorithm: String):Verify
    public fun getHashes(): Array<String>
    public fun createPrivateKey(key: KeyDef):KeyObject
    public fun createPublicKey(key: KeyDef):KeyObject
}

public external interface KeyDef {
    public var key: dynamic
    public var format: String
    public var encoding: String
}

public external class Hmac {
    public fun update(data: Uint8Array)
    public fun update(data: String, encoding: String)
    public fun digest(): Buffer
    public fun digest(encoding: String): String
}

public external class Sign {
    public fun update(data: Uint8Array)
    public fun update(data: String, encoding: String)
    public fun sign(key: KeyObject): Buffer
    public fun sign(key: KeyObject, encoding: String): String
}

public external class Verify {
    public fun update(data: Uint8Array)
    public fun update(data: String, encoding: String)
    public fun verify(key: KeyObject, signature: Uint8Array): Boolean
    public fun verify(key: KeyObject, signature: Uint8Array, encoding: String): Boolean
}

public external interface KeyObject {
    public val asymmetricKeyType: String?
    public val type: String
}
public fun KeyObject.wrap(): JSKeyObject = JSKeyObject(this)

public fun JsonWebKey.toKeyObjectPrivate(): KeyObject = Crypto.createPrivateKey(objectOf<KeyDef> {
    val encodeToString = JsonWebKey.format.encodeToString(this@toKeyObjectPrivate)
    key = js("JSON.parse(encodeToString)")
    format = "jwk"
    encoding = "utf8"
})
public fun JsonWebKey.toKeyObjectPublic(): KeyObject = Crypto.createPublicKey(objectOf<KeyDef> {
    val encodeToString = JsonWebKey.format.encodeToString(this@toKeyObjectPublic)
    key = js("JSON.parse(encodeToString)")
    format = "jwk"
    encoding = "utf8"
})

public data class JSKeyObject(val key: KeyObject): SigningKey

internal inline fun <I> objectOf(
    jsonObject: I = js("new Object()").unsafeCast<I>(),
    writer: I.() -> Unit
): I {
    writer(jsonObject)
    return jsonObject
}