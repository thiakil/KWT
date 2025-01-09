

package com.thiakil.kwt.algorithms

import com.thiakil.kwt.*

/**
 * None algorithm, only useful for [JWS.sign] and its Id
 */
public object None: JwsAlgorithm {
    override val jwaId: JWS.Id = JWS.Id.NONE

    override fun verify(signature: UnverifiedSignature, key: SigningKey): Boolean {
        return signature.signature.isEmpty()
    }

    override fun sign(payload: String, key: SigningKey): String = ""
}
