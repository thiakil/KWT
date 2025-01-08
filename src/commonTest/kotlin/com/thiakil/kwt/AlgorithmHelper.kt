

package com.thiakil.kwt

import kotlin.test.*

object AlgorithmHelper {
    fun testSelfSignVerify(jwt: JWTPayload, algorithm: JwsAlgorithm, keyIn: SigningKey) {
        val signed = jwt.sign {
            key = keyIn
            alg = algorithm
        }
        val decodedJWT = JWT.decode(signed)
        assertTrue(algorithm.verify(decodedJWT.signature!!, keyIn))
        assertTrue(JWS.verify(decodedJWT, keyIn, false))
    }
}
