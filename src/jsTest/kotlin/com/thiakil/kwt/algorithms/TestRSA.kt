package com.thiakil.kwt.algorithms

import node.Crypto
import node.objectOf
import node.wrap
import kotlin.test.Test

class TestRSA:RSATests(
    Crypto.createPublicKey(objectOf {
        key = "-----BEGIN PUBLIC KEY-----\n"+publicKeyPEM+"\n-----END PUBLIC KEY-----"
        format = "pem"
        encoding = "utf8"
    }).wrap(),
    Crypto.createPrivateKey(objectOf {
        key = "-----BEGIN PRIVATE KEY-----\n"+privateKeyPEM+"\n-----END PRIVATE KEY-----"
        format = "pem"
        encoding = "utf8"
    }).wrap()
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
