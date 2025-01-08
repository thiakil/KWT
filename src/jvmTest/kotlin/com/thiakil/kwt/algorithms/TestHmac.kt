

package com.thiakil.kwt.algorithms

import com.thiakil.kwt.*
import com.thiakil.kwt.algorithms.*
import kotlinx.coroutines.*
import kotlin.test.*


class TestHmac {
    @Test
    fun testHS256() {
        //signed with secret bytes the UTF-8 string "test"
        val token =
            JWT.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MDgzMDE3MTh9.0fw6h3xOPG_Ptqy7Wt-wIi8TX4H6d9p2hi5radQGojU")
        assertEquals(HS256.jwaId, token.header.algorithm)
        val correctKey = HmacStringKey("test")
        assertTrue(JWS.verify(token, correctKey))
        assertTrue(HS256.verify(token.signature!!, correctKey))
        assertFalse(HS256.verify(token.signature!!, HmacStringKey("not-the-right-key")))
    }

    @Test
    fun testHS256Sign() {
        val key = HmacStringKey("test")
        val signed = runBlocking { JWS.sign(baseToken, HS256, key ) }
        assertTrue(HS256.verify(JWT.decode(signed).signature!!, key))
    }

    @Test
    fun testHS256SignDSL() {
        val hmackey = HmacStringKey("test")
        val signed = baseToken.sign {
            alg = HS256
            key = hmackey
        }
        assertTrue(HS256.verify(JWT.decode(signed).signature!!, hmackey))
    }

    @Test
    fun testSignVerifyLoop() {
        AlgorithmHelper.testSelfSignVerify(baseToken, HS256, HmacByteKey(byteArrayOf(1,2,3,4,5,6)))
        AlgorithmHelper.testSelfSignVerify(baseToken, HS384, HmacByteKey(byteArrayOf(1,2,3,4,5,6)))
        AlgorithmHelper.testSelfSignVerify(baseToken, HS512, HmacByteKey(byteArrayOf(1,2,3,4,5,6)))
    }

    private val baseToken = makeJWT {
        issuer = "test-issuer"
        singleAudience = "test"
        subject = "test testerton"
    }
}