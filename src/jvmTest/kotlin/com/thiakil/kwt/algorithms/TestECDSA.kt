package com.thiakil.kwt.algorithms

import kotlin.test.Test

class TestECDSA: ECDSATests(
    //really need to get these separate, not really testing anything new here
    JavaECKey(null, ecKey.toJavaPrivate()),
    JavaECKey(ecKey.toJavaPublic())
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
