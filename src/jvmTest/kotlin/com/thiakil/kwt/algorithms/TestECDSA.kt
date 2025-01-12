package com.thiakil.kwt.algorithms

import io.ktor.util.decodeBase64Bytes
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.test.Test

val platformKey256 = JavaECKey(
    publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(ECDSATests.ecKey256PublicDER.decodeBase64Bytes())) as ECPublicKey,
    privateKey = KeyFactory.getInstance("EC")
        .generatePrivate(PKCS8EncodedKeySpec(ECDSATests.ecKey256PrivateDER.decodeBase64Bytes())) as ECPrivateKey
)

val platformKey521 = JavaECKey(
    publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(ECDSATests.ecKey521PublicDER.decodeBase64Bytes())) as ECPublicKey,
    privateKey = KeyFactory.getInstance("EC")
        .generatePrivate(PKCS8EncodedKeySpec(ECDSATests.ecKey521PrivateDER.decodeBase64Bytes())) as ECPrivateKey
)

class TestECDSA: ECDSATests(
    platformKey256,
    platformKey256,
    platformKey521,
    platformKey521
) {
    @Test
    override fun testES256Verify() {
        testES256Verify_()
    }

    @Test
    override fun testES512Verify() {
        testES512Verify_()
    }

    @Test
    override fun testSignVerifyLoop(){
        testSignVerifyLoop_()
    }
}
