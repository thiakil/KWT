package com.thiakil.kwt.algorithms

import com.thiakil.kwt.AlgorithmHelper
import com.thiakil.kwt.JOSEHeaderData
import com.thiakil.kwt.JWS
import com.thiakil.kwt.JWT
import com.thiakil.kwt.jwt
import com.thiakil.kwt.sign
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

abstract class HMACTests {
    private val HS256 = JWS[JWS.Id.HS256]
    private val HS384 = JWS[JWS.Id.HS384]
    private val HS512 = JWS[JWS.Id.HS512]

    abstract fun testHS256()
    fun testHS256_() {
        //signed with secret bytes the UTF-8 string "test"
        val token =
            JWT.decodeUnverified("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MDgzMDE3MTh9.0fw6h3xOPG_Ptqy7Wt-wIi8TX4H6d9p2hi5radQGojU")
        assertEquals(HS256.jwaId, token.header.algorithm)
        val correctKey = HmacStringKey("test")
        assertEquals(HS256.jwaId, token.header.algorithm)
        assertTrue(HS256.verify(token.signature!!, correctKey))
        assertFalse(HS256.verify(token.signature!!, HmacStringKey("not-the-right-key")))
    }

    abstract fun testHS256SignDSL()
    fun testHS256SignDSL_() {
        val key = HmacStringKey("test")
        val signed = baseToken.sign {
            type = "jwt"
            algorithm = JWS.Id.HS256
            this.key = key
        }
        assertTrue(HS256.verify(JWT.decodeUnverified(signed).signature!!, key))
    }

    abstract fun testHS256Sign()
    fun testHS256Sign_() {
        val hmackey = HmacStringKey("test")
        val signed = baseToken.sign(JOSEHeaderData(algorithm = JWS.Id.HS256), HS256, hmackey)
        assertTrue(HS256.verify(JWT.decodeUnverified(signed).signature!!, hmackey))
    }

    abstract fun testSignVerifyLoop()
    fun testSignVerifyLoop_() {
        AlgorithmHelper.testSelfSignVerify(baseToken, HS256, HmacByteKey(byteArrayOf(1, 2, 3, 4, 5, 6)))
        AlgorithmHelper.testSelfSignVerify(baseToken, HS384, HmacByteKey(byteArrayOf(1, 2, 3, 4, 5, 6)))
        AlgorithmHelper.testSelfSignVerify(baseToken, HS512, HmacByteKey(byteArrayOf(1, 2, 3, 4, 5, 6)))
    }

    private val baseToken = jwt {
        issuer = "test-issuer"
        singleAudience = "test"
        subject = "test testerton"
    }
}