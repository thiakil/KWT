package com.thiakil.kwt.algorithms

import com.thiakil.kwt.AlgorithmHelper
import com.thiakil.kwt.JWS
import com.thiakil.kwt.JWT
import com.thiakil.kwt.JsonWebKey
import com.thiakil.kwt.SigningKey
import com.thiakil.kwt.jwt
import com.thiakil.kwt.sign
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

abstract class ECDSATests(
    private val platformKeyPrivate: SigningKey,
    private val platformKeyPublic: SigningKey
) {
    private val ES256 = JWS[JWS.Id.ES256]
    private val ES384 = JWS[JWS.Id.ES384]
    private val ES512 = JWS[JWS.Id.ES512]

    abstract fun testES256Verify()
    fun testES256Verify_() {
        val jwt = JWT.decodeUnverified(encodedJwt)
        assertEquals(ES256.jwaId, jwt.header.algorithm)
        assertNotNull(jwt.signature)
        assertTrue(ES256.verify(jwt.signature!!, ecKey))
        assertTrue(ES256.verify(jwt.signature!!, platformKeyPublic))

        //re-sign it with the same key and test it passes verification
        val signed = jwt.payload.sign {
            type = "jwt"
            algorithm = JWS.Id.ES256
            key = ecKey
        }
        val reDecoded = JWT.decodeUnverified(signed)
        assertNotNull(reDecoded.signature)
        assertTrue(ES256.verify(reDecoded.signature!!, ecKey))

        //re-sign it with the same key and test it passes verification
        val signedNative = jwt.payload.sign {
            type = "jwt"
            algorithm = JWS.Id.ES256
            key = platformKeyPrivate
        }
        val reDecodedNative = JWT.decodeUnverified(signedNative)
        assertNotNull(reDecodedNative.signature)
        assertTrue(ES256.verify(reDecodedNative.signature!!, ecKey))
    }

    abstract fun testSignVerifyLoop()
    fun testSignVerifyLoop_(){
        val baseToken = jwt {
            issuer = "test-issuer"
            singleAudience = "test"
            subject = "test testerton"
        }
        AlgorithmHelper.testSelfSignVerify(baseToken, ES256, ecKey)
        AlgorithmHelper.testSelfSignVerify(baseToken, ES384, ecKey)
        AlgorithmHelper.testSelfSignVerify(baseToken, ES512, ecKey)
    }

    companion object {
        // https://tools.ietf.org/html/rfc7515#appendix-A.3
        internal val ecKey = JsonWebKey.format.decodeFromString<JsonWebKey.EllipticCurve>(
            """{"kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
     }"""
        )
        private val encodedJwt = "eyJhbGciOiJFUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    }
}