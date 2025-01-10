

package com.thiakil.kwt.algorithms

import com.thiakil.kwt.AlgorithmHelper
import com.thiakil.kwt.JWS
import com.thiakil.kwt.JWT
import com.thiakil.kwt.JsonWebKey
import com.thiakil.kwt.jwt
import com.thiakil.kwt.sign
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TestECDSA {
    @Test
    fun testES256Verify() {
        val jwt = JWT.decodeUnverified(encodedJwt)
        assertEquals(ES256.jwaId, jwt.header.algorithm)
        assertNotNull(jwt.signature)
        assertTrue(ES256.verify(jwt.signature!!, ecKey))
        assertTrue(ES256.verify(jwt.signature!!, JavaECKey(ecKey.toJavaPublic())))

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
            key = JavaECKey(null, ecKey.toJavaPrivate())
        }
        val reDecodedNative = JWT.decodeUnverified(signedNative)
        assertNotNull(reDecodedNative.signature)
        assertTrue(ES256.verify(reDecodedNative.signature!!, ecKey))
    }

    @Test
    fun testSignVerifyLoop(){
        val baseToken = jwt {
            issuer = "test-issuer"
            singleAudience = "test"
            subject = "test testerton"
        }
        AlgorithmHelper.testSelfSignVerify(baseToken, ES256, ecKey)
        AlgorithmHelper.testSelfSignVerify(baseToken, ES384, ecKey)
        AlgorithmHelper.testSelfSignVerify(baseToken, ES512, ecKey)
    }

    // https://tools.ietf.org/html/rfc7515#appendix-A.3
    private val ecKey = JsonWebKey.format.decodeFromString<JsonWebKey.EllipticCurve>("""{"kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
     }""")
    private val encodedJwt = "eyJhbGciOiJFUzI1NiJ9" +
        "." +
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
        "." +
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
}
