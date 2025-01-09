

package com.thiakil.kwt

import kotlin.test.*

object AlgorithmHelper {
    fun testSelfSignVerify(jwt: JWTPayload, algorithm: JwsAlgorithm, keyIn: SigningKey) {
        val payload = jwt.serialise(JOSEHeaderData(algorithm = algorithm.jwaId))
        val signed = "${payload}.${algorithm.sign(payload, keyIn)}"
        println("${algorithm.jwaId}: $signed")
        val decodedJWT = JWT.decode(signed)
        assertEquals(algorithm.jwaId, decodedJWT.header.algorithm)
        assertTrue(algorithm.verify(decodedJWT.signature!!, keyIn))
    }
}
