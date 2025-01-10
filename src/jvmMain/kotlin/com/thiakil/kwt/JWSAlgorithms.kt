

package com.thiakil.kwt

import com.thiakil.kwt.algorithms.ES256
import com.thiakil.kwt.algorithms.ES384
import com.thiakil.kwt.algorithms.ES512
import com.thiakil.kwt.algorithms.HS256
import com.thiakil.kwt.algorithms.HS384
import com.thiakil.kwt.algorithms.HS512
import com.thiakil.kwt.algorithms.PS256
import com.thiakil.kwt.algorithms.PS384
import com.thiakil.kwt.algorithms.PS512
import com.thiakil.kwt.algorithms.RS256
import com.thiakil.kwt.algorithms.RS384
import com.thiakil.kwt.algorithms.RS512

internal actual val JWS_ALGORITHMS: Map<JWS.Id, JwsAlgorithm> = listOf(
    ES256, ES384, ES512,
    HS256, HS384, HS512,
    PS256, PS384, PS512,
    RS256, RS384, RS512
).associateBy { it.jwaId }
