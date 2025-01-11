

package com.thiakil.kwt.algorithms

import io.ktor.util.decodeBase64Bytes
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.test.Test

class TestRSA:RSATests(
    JavaRSAKey(KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(publicKeyPEM.decodeBase64Bytes())) as RSAPublicKey),
    JavaRSAKey(privateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKeyPEM.decodeBase64Bytes())) as RSAPrivateKey)
) {

    @Test
    override fun testRSASignature() {
        testRSASignature_()
    }

    @Test
    override fun testJWKRSASig() {
        testJWKRSASig_()
    }

    @Test
    override fun testSignWithJwk() {
        testSignWithJwk_()
    }

    @Test
    override fun testSignAndVerify() {
        testSignAndVerify_()
    }

    @Test
    override fun testSignVerifyLoop() {
        testSignVerifyLoop_()
    }

}
