package com.thiakil.kwt.algorithms

import kotlin.test.Test

class TestHmac: HMACTests() {
    @Test
    override fun testHS256() {
        testHS256_()
    }

    @Test
    override fun testHS256SignDSL() {
        testHS256SignDSL_()
    }

    @Test
    override fun testHS256Sign() {
        testHS256Sign_()
    }

    @Test
    override fun testSignVerifyLoop() {
        testSignVerifyLoop_()
    }
}
