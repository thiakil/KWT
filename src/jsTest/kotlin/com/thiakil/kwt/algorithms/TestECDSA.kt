package com.thiakil.kwt.algorithms

import node.Crypto
import node.NodeBuffer
import node.objectOf
import node.wrap
import kotlin.test.Test

class TestECDSA: ECDSATests(
    Crypto.createPrivateKey(objectOf {
        key = NodeBuffer.Buffer.from(ecKey256PrivateDER, "base64")
        format = "der"
        type = "pkcs8"
    }).wrap(),
    Crypto.createPublicKey(objectOf {
        key = NodeBuffer.Buffer.from(ecKey256PublicDER, "base64")
        format = "der"
        type = "spki"
    }).wrap(),
    Crypto.createPrivateKey(objectOf {
        key = NodeBuffer.Buffer.from(ecKey521PrivateDER, "base64")
        format = "der"
        type = "pkcs8"
    }).wrap(),
    Crypto.createPublicKey(objectOf {
        key = NodeBuffer.Buffer.from(ecKey521PublicDER, "base64")
        format = "der"
        type = "spki"
    }).wrap(),
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
