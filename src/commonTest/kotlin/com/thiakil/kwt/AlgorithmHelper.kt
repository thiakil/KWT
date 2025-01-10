

package com.thiakil.kwt

import com.thiakil.kwt.algorithms.UnsignedAlg
import kotlin.test.*

object AlgorithmHelper {
    fun testSelfSignVerify(jwt: JWTPayload, algorithm: JwsAlgorithm, keyIn: SigningKey) {
        val signed = jwt.sign(JOSEHeaderData(algorithm = algorithm.jwaId), algorithm, keyIn)
        println("${algorithm.jwaId}: $signed")
        val decodedJWT = JWT.decodeUnverified(signed)
        assertEquals(algorithm.jwaId, decodedJWT.header.algorithm)
        if (algorithm != UnsignedAlg) {
            assertNotNull(decodedJWT.signature, "expected a signature")
            val allInOne = JWT.validate(signed, keyIn)
            assertEquals(jwt.getFields(), allInOne.getFields())
        }
        //handle none algo
        val signature = decodedJWT.signature ?: UnverifiedSignature("", ByteArray(0))
        assertTrue(algorithm.verify(signature, keyIn))
        assertEquals(jwt.getFields(), decodedJWT.payload.getFields())
    }
}
