

package com.thiakil.kwt

import kotlin.test.*

object AlgorithmHelper {
    fun testSelfSignVerify(jwt: JWTPayload, algorithm: JwsAlgorithm, keyIn: SigningKey) {
        val signed = jwt.sign {
            key = keyIn
            alg = algorithm
        }
        println("${algorithm.jwaId}: $signed")
        val decodedJWT = JWT.decode(signed)
        assertEquals(algorithm.jwaId, decodedJWT.header.algorithm)
        assertTrue(algorithm.verify(decodedJWT.signature!!, keyIn))
    }
}
