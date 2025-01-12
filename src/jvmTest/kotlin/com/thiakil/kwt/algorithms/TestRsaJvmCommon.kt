package com.thiakil.kwt.algorithms

import com.thiakil.kwt.JOSEHeaderData
import com.thiakil.kwt.JWS
import com.thiakil.kwt.JWT
import com.thiakil.kwt.JsonWebKey
import com.thiakil.kwt.jwt
import com.thiakil.kwt.sign
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TestRsaJvmCommon {
    @Test
    fun testJvmToJwk(){
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048, SecureRandom())
        }.generateKeyPair()
        val platformPrivateKey = keyPair.private as RSAPrivateKey
        val platformPublicKey = keyPair.public as RSAPublicKey

        val signedToken = jwt {
            issuer = "TestRsaJvmCommon"
            subject = "testing"
        }.sign {
            algorithm = JWS.Id.RS256
            key = JavaRSAKey(privateKey = platformPrivateKey)
        }
        val decodedToken = JWT.decodeUnverified(signedToken)

        //test public and private works
        var newJwk = JsonWebKey.RSA(
            privateKey = platformPrivateKey,
            publicKey = platformPublicKey
        )
        assertTrue(newJwk.isValidPrivateKey)
        assertTrue(newJwk.isValidPublicKey)
        assertTrue(RS256.verify(decodedToken.signature!!, newJwk))

        //test just public (produces only a valid public key)
        newJwk = JsonWebKey.RSA(
            publicKey = platformPublicKey
        )

        assertTrue(newJwk.isValidPublicKey)
        assertFalse(newJwk.isValidPrivateKey)
        assertTrue(RS256.verify(decodedToken.signature!!, newJwk))

        //test just private, which should have enough info for the public
        newJwk = JsonWebKey.RSA(
            privateKey = platformPrivateKey,
        )
        assertTrue(newJwk.isValidPrivateKey)
        assertTrue(newJwk.isValidPublicKey)
        assertTrue(RS256.verify(decodedToken.signature!!, newJwk))
    }

    @Test
    fun testJvmJwkCompatibility() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048, SecureRandom())
        }.generateKeyPair()

        val newJwk = JsonWebKey.RSA(
            privateKey = keyPair.private as RSAPrivateKey,
            publicKey = keyPair.public as RSAPublicKey
        )
        assertTrue(newJwk.isValidPrivateKey)
        assertTrue(newJwk.isValidPublicKey)

        val baseToken = jwt {
            issuer = "test-issuer"
            singleAudience = "test"
            subject = "test testerton"
        }

        val nativeKey = JavaRSAKey(keyPair)

        //test signing via native and verifying by jwk
        val jvmSigned = baseToken.sign(JOSEHeaderData(algorithm = JWS.Id.RS256), RS256, nativeKey)
        assertTrue(RS256.verify(JWT.decodeUnverified(jvmSigned).signature!!, newJwk))

        //test signing via JWK and verifying via native
        val jwkSigned = baseToken.sign(JOSEHeaderData(algorithm = JWS.Id.RS256), RS256, newJwk)
        assertTrue(RS256.verify(JWT.decodeUnverified(jwkSigned).signature!!, nativeKey))
    }
}
