

package com.thiakil.kwt.algorithms

import com.thiakil.kwt.*

/**
 * None algorithm, generates an unsigned JWT. Use with caution.
 */
public object UnsignedAlg: JwsAlgorithm {
    override val jwaId: JWS.Id = JWS.Id.NONE

    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        return signature.signature.isEmpty()
    }

    override fun sign(payload: String, key: SigningKey): String = ""
}
