

package com.thiakil.kwt

import kotlin.test.*

object AlgorithmHelper {
    fun testSelfSignVerify(jwt: JWTPayload, algorithm: JwsAlgorithm, keyIn: SigningKey) {
        val signed = jwt.signSync {
            key = keyIn
            alg = algorithm
        }
        assertTrue(algorithm.verify(JWT.decode(signed).signature!!, keyIn))
    }
}
