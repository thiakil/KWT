package com.thiakil.kwt.algorithms

import node.Crypto
import node.NodeBuffer
import node.objectOf
import node.wrap
import kotlin.test.Test

class TestECDSA: ECDSATests(
    createPrivate(ecKey256PrivateDER),
    createPublic(ecKey256PublicDER),
    createPrivate(ecKey384PrivateDER),
    createPublic(ecKey384PublicDER),
    createPrivate(ecKey521PrivateDER),
    createPublic(ecKey521PublicDER)
) {

}

private fun createPublic(keyData: String) = Crypto.createPublicKey(objectOf {
    key = NodeBuffer.Buffer.from(keyData, "base64")
    format = "der"
    type = "spki"
}).wrap()

private fun createPrivate(keyData: String) = Crypto.createPrivateKey(objectOf {
    key = NodeBuffer.Buffer.from(keyData, "base64")
    format = "der"
    type = "pkcs8"
}).wrap()
