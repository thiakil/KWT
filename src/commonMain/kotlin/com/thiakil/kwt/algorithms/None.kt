

package com.thiakil.kwt.algorithms

import com.thiakil.kwt.*

/**
 * None algorithm, only useful for [JWS.sign] and it's Id
 */
public object None: JwsAlgorithm {
    override val jwaId: String = "none"

    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        return signature.signature.isEmpty()
    }

    override fun sign(payload: String, key: SigningKey): String = ""
}
