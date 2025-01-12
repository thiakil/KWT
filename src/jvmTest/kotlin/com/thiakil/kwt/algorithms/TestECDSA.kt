package com.thiakil.kwt.algorithms

import io.ktor.util.decodeBase64Bytes
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.test.Test

val keyFactory = KeyFactory.getInstance("EC")

private fun makeEcKey(publicDER: String, privateDER: String): JavaECKey {
    return JavaECKey(
        publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicDER.decodeBase64Bytes())) as ECPublicKey,
        privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateDER.decodeBase64Bytes())) as ECPrivateKey
    )
}

val platformKey256 = makeEcKey(ECDSATests.ecKey256PublicDER, ECDSATests.ecKey256PrivateDER)
val platformKey384 = makeEcKey(ECDSATests.ecKey384PublicDER, ECDSATests.ecKey384PrivateDER)
val platformKey521 = makeEcKey(ECDSATests.ecKey521PublicDER, ECDSATests.ecKey521PrivateDER)

class TestECDSA: ECDSATests(
    platformKey256,
    platformKey256,
    platformKey384,
    platformKey384,
    platformKey521,
    platformKey521
) {

}
