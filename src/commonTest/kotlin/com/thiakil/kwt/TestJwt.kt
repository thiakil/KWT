

package com.thiakil.kwt

import com.thiakil.kwt.algorithms.UnsignedAlg
import io.ktor.util.date.*
import kotlinx.serialization.json.*
import kotlin.test.*

class TestJwt {
    private val basicEncodedJWT = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    @Test
    fun decodeBasic() {
        val decoded = JWT.decodeUnverified(basicEncodedJWT)
        assertEquals(JWS.Id.HS256, decoded.header.algorithm, "Header parse failed")
        assertEquals("JWT", decoded.header.type, "Header parse failed")
        assertEquals("joe", decoded.payload.issuer)
        assertEquals(GMTDate(1300819380L * 1000), decoded.payload.expiresAt)
        assertTrue(decoded.payload.unknownClaims.containsKey("http://example.com/is_root"))
        val isRoot = decoded.payload.unknownClaims["http://example.com/is_root"]
        assertTrue(isRoot is JsonPrimitive)
        assertEquals("true", isRoot.content)
    }

    @Test
    fun decodeUnsigned() {
        val decoded = JWT.decodeUnverified("eyJhbGciOiJub25lIn0." +
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.")
        assertEquals(JWS.Id.NONE, decoded.header.algorithm)
        assertEquals("joe", decoded.payload.issuer)
        assertNull(decoded.signature)
    }

    @Test
    fun signLoopUnsigned() {
        AlgorithmHelper.testSelfSignVerify(
            makeJWT {
                issuer = "example.com"
                singleAudience = "example"
                givenName = "Test"
                familyName = "Testerton"
            },
            UnsignedAlg,
            SigningKey.NONE
        )
    }
}
