package com.thiakil.kwt

import com.thiakil.kwt.algorithms.HS256
import com.thiakil.kwt.algorithms.HS384
import com.thiakil.kwt.algorithms.HS512

internal actual val JWS_ALGORITHMS: Map<JWS.Id, JwsAlgorithm> = listOf(
    HS256, HS384, HS512
).associateBy { it.jwaId }