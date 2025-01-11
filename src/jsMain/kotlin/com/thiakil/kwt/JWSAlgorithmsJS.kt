package com.thiakil.kwt

import com.thiakil.kwt.algorithms.ES256
import com.thiakil.kwt.algorithms.ES384
import com.thiakil.kwt.algorithms.ES512
import com.thiakil.kwt.algorithms.HS256
import com.thiakil.kwt.algorithms.HS384
import com.thiakil.kwt.algorithms.HS512
import com.thiakil.kwt.algorithms.RS256
import com.thiakil.kwt.algorithms.RS384
import com.thiakil.kwt.algorithms.RS512

internal actual val JWS_ALGORITHMS: Map<JWS.Id, JwsAlgorithm> = listOf(
    HS256, HS384, HS512,
    RS256, RS384, RS512,
    ES256, ES384, ES512
).associateBy { it.jwaId }