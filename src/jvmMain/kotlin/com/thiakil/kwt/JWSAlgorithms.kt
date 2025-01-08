

package com.thiakil.kwt

import com.thiakil.kwt.algorithms.*

internal actual val JWS_ALGORITHMS: Map<String, JwsAlgorithm> = listOf(
    ES256, ES384, ES512,
    HS256, HS384, HS512,
    PS256, PS384, PS512,
    RS256, RS384, RS512
).map { Pair(it.jwaId, it) }.toMap()
