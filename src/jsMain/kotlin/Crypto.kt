@JsModule("node:crypto")
public external object Crypto {
    public fun createHmac(algorithm: String, key: String): Hmac
    public fun createHmac(algorithm: String, key: ByteArray): Hmac
}

public external class Hmac {
    public fun update(data: ByteArray)
    public fun update(data: String)
    public fun update(data: String, encoding: String)
    public fun digest(): ByteArray
    public fun digest(encoding: String): String
}