package com.thiakil.kwt.algorithms

import com.thiakil.kwt.AlgorithmHelper
import com.thiakil.kwt.JOSEHeaderData
import com.thiakil.kwt.JWS
import com.thiakil.kwt.JWT
import com.thiakil.kwt.jwt
import com.thiakil.kwt.sign
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TestHmac {
    @Test
    fun testHS256() {
        //signed with secret bytes the UTF-8 string "test"
        val token =
            JWT.decodeUnverified("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MDgzMDE3MTh9.0fw6h3xOPG_Ptqy7Wt-wIi8TX4H6d9p2hi5radQGojU")
        assertEquals(HS256.jwaId, token.header.algorithm)
        val correctKey = HmacStringKey("test")
        assertEquals(HS256.jwaId, token.header.algorithm)
        assertTrue(HS256.verify(token.signature!!, correctKey))
        assertFalse(HS256.verify(token.signature!!, HmacStringKey("not-the-right-key")))
    }

    @Test
    fun testHS256Sign() {
        val key = HmacStringKey("test")
        val signed = baseToken.sign {
            type = "jwt"
            algorithm = JWS.Id.HS256
            this.key = key
        }
        assertTrue(HS256.verify(JWT.decodeUnverified(signed).signature!!, key))
    }

    @Test
    fun testHS256SignDSL() {
        val hmackey = HmacStringKey("test")
        val signed = baseToken.sign(JOSEHeaderData(algorithm = JWS.Id.HS256), HS256, hmackey)
        assertTrue(HS256.verify(JWT.decodeUnverified(signed).signature!!, hmackey))
    }

    @Test
    fun testSignVerifyLoop() {
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
