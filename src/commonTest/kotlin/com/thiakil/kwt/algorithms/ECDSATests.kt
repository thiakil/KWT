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
    private val platformKeyPrivate256: SigningKey,
    private val platformKeyPublic256: SigningKey,
    private val platformKeyPrivate521: SigningKey,
    private val platformKeyPublic521: SigningKey
) {
    private val ES256 = JWS[JWS.Id.ES256]
    private val ES384 = JWS[JWS.Id.ES384]
    private val ES512 = JWS[JWS.Id.ES512]

    abstract fun testES256Verify()
    fun testES256Verify_() {
        val jwt = JWT.decodeUnverified(encodedJwt256)
        assertEquals(ES256.jwaId, jwt.header.algorithm)
        assertNotNull(jwt.signature)
        assertTrue(ES256.verify(jwt.signature!!, ecKey256))
        assertTrue(ES256.verify(jwt.signature!!, platformKeyPublic256))

        //re-sign it with the same key and test it passes verification
        val signed = jwt.payload.sign {
            type = "jwt"
            algorithm = JWS.Id.ES256
            key = ecKey256
        }
        val reDecoded = JWT.decodeUnverified(signed)
        assertNotNull(reDecoded.signature)
        assertTrue(ES256.verify(reDecoded.signature!!, ecKey256))

        //re-sign it with the same key and test it passes verification
        val signedNative = jwt.payload.sign {
            type = "jwt"
            algorithm = JWS.Id.ES256
            key = platformKeyPrivate256
        }
        val reDecodedNative = JWT.decodeUnverified(signedNative)
        assertNotNull(reDecodedNative.signature)
        assertTrue(ES256.verify(reDecodedNative.signature!!, ecKey256))
    }

    abstract fun testES512Verify()
    fun testES512Verify_() {
        val jwt = JWT.decodeUnverified(encodedJwt512)
        assertEquals(ES512.jwaId, jwt.header.algorithm)
        assertNotNull(jwt.signature)
        assertTrue(ES512.verify(jwt.signature!!, ecKey521))
        assertTrue(ES512.verify(jwt.signature!!, platformKeyPublic521))

        //re-sign it with the same key and test it passes verification
        val signed = jwt.payload.sign {
            type = "jwt"
            algorithm = JWS.Id.ES512
            key = ecKey521
        }
        val reDecoded = JWT.decodeUnverified(signed)
        assertNotNull(reDecoded.signature)
        assertTrue(ES512.verify(reDecoded.signature!!, ecKey521))

        //re-sign it with the same key and test it passes verification
        val signedNative = jwt.payload.sign {
            type = "jwt"
            algorithm = JWS.Id.ES512
            key = platformKeyPrivate521
        }
        val reDecodedNative = JWT.decodeUnverified(signedNative)
        assertNotNull(reDecodedNative.signature)
        assertTrue(ES512.verify(reDecodedNative.signature!!, ecKey521))
    }

    abstract fun testSignVerifyLoop()
    fun testSignVerifyLoop_(){
        val baseToken = jwt {
            issuer = "test-issuer"
            singleAudience = "test"
            subject = "test testerton"
        }
        AlgorithmHelper.testSelfSignVerify(baseToken, ES256, ecKey256)
        //AlgorithmHelper.testSelfSignVerify(baseToken, ES384, ecKey256) TODO need the right key
        AlgorithmHelper.testSelfSignVerify(baseToken, ES512, ecKey521)
    }

    companion object {
        // https://tools.ietf.org/html/rfc7515#appendix-A.3
        internal val ecKey256 = JsonWebKey.format.decodeFromString<JsonWebKey.EllipticCurve>(
            """{"kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
     }"""
        )
        internal val ecKey256PrivateDER = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjpsQnnGQmL+YBIff" +
                "H1136cspYG6+0iY7X1fCE9+E9LKhRANCAAR/zc4ncPbEXUGDy+5v20t7WAczNXvp" +
                "7xO6z248e9FURcfxRM0bvZt+hyzf7bnuufSzaV1uqQskrYpGIyiFiOWt"
        internal val ecKey256PublicDER = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRV" +
                "EXH8UTNG72bfocs3+257rn0s2ldbqkLJK2KRiMohYjlrQ=="

        //https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.4
        internal val ecKey521 = JsonWebKey.format.decodeFromString<JsonWebKey.EllipticCurve>(
            """{ "kty":"EC", "crv":"P-521", "x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk", "y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2", "d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C" }"""
        )
        internal val ecKey521PrivateDER = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBjmlvsDRQWIHdEQtIPrh9Ms5JX+NrN0Xt8tjK5PDyU59GFaDpjqtSs8DF6sTOB1GFqOe7R96sHR3ne8z2YTXmPYKhgYkDgYYABAHpKQUPEk/GvFXH1TkzZd+d70qwwiyyV5j5NOsE48a643AaV6eRDp2BvzYxWejryxVdY0n0vbbM+KlMXFnHqsEBpAA0pkQON2dQ0jcf0b3CyPO3HS9O5eo0MsgVzKMVYP5dk4fsd0tVg4Yw5cu/Woy+CpHdAGTGmZofbm5n+t3t5MjI9g=="
        internal val ecKey521PublicDER = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB6SkFDxJPxrxVx9U5M2Xfne9KsMIssleY+TTrBOPGuuNwGlenkQ6dgb82MVno68sVXWNJ9L22zPipTFxZx6rBAaQANKZEDjdnUNI3H9G9wsjztx0vTuXqNDLIFcyjFWD+XZOH7HdLVYOGMOXLv1qMvgqR3QBkxpmaH25uZ/rd7eTIyPY="
        private val encodedJwt256 = "eyJhbGciOiJFUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        private val encodedJwt512 = "eyJhbGciOiJFUzUxMiJ9.eyJ0ZXN0IjoiZm9vIn0." +
                "AGlDSCsM8BxI7QYLaCLKR1EIKWun4KlKu9QfM-CIe75RekFatt7_wl6X0JlzJEuHs_v-YkRi94WLnZC3NEpYifDPAcgTtCkRQP" +
                "SiwTW_hCwqb7P0ZFvjgSivmc4fdtHWq-VgrJ5vHtVJz3MjOlYeemcAB_-W3CIZhK2yT92f8GzwJRS_"
    }
}