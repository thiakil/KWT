package com.thiakil.kwt.algorithms

import node.toKeyObjectPrivate
import node.toKeyObjectPublic
import node.wrap
import kotlin.test.Test

class TestECDSA: ECDSATests(
    //really need to get these separate, not really testing anything new here
    ecKey.toKeyObjectPrivate().wrap(),
    ecKey.toKeyObjectPublic().wrap()
) {
    @Test
    override fun testES256Verify() {
        testES256Verify_()
    }

    @Test
    override fun testSignVerifyLoop(){
        testSignVerifyLoop_()
    }
}
