Kotlin Web Tokens (KWT)
=======================
KWT is a Kotlin multiplatform library for creating and verifying [JSON Web Tokens](https://jwt.io/introduction) (JWT) in compact serialised form (JWS). JSON Web Keys (JWK) are also supported and can be created from some platform native keys.

Originally it was intended to be added to Ktor as another Auth algorithm that was available on more than just JVM, but I decided it might also be useful outside Ktor in Kotlin-jvm projects.

Specific sign/verify algorithms are platform dependent, as it doesn't make much sense to reimplement them from scratch.
Platforms without sign/verify support are able to decode a JWT's contents (insecurely) and produce unsigned JWT.

| Algorithm | JVM | NodeJS | Linux | MinGW64 |
|-----------|-----|--------|-------|---------|
| RS256     | ✅   |        |       |         |
| RS384     | ✅   |        |       |         |
| RS512     | ✅   |        |       |         |
| HS256     | ✅   |   ✅    |       |         |
| HS384     | ✅   |   ✅    |       |         |
| HS512     | ✅   |   ✅    |       |         |
| ES256     | ✅   |        |       |         |
| ES384     | ✅   |        |       |         |
| ES512     | ✅   |        |       |         |
| PS256     | ✅   |        |       |         |
| PS384     | ✅   |        |       |         |
| PS512     | ✅   |        |       |         |

## Getting Started

### Add Dependency
TODO

```kotlin
kotlin {
    sourceSets {
        commonMain {
            dependencies {
                implementation("com.thiakil:KWT:$kwt_version")
            }
        }
    }
}
```

### Basic JWT Generation

```kotlin
val hmacKey = HmacStringKey("This is my key")

val token: String = jwt {
    issuer = "test-issuer"
    singleAudience = "test"
    subject = "test testerton"
}.sign {
    alg = JWS.Id.HS256
    key = hmacKey
}
println(token)
```

### Basic JWT Verification

```kotlin
val hmacKey = HmacStringKey("This is my key")
val token: String = "<token from above>"

val decoded: JWTPayload = JWT.validate(token, hmacKey)

// NB: at this point you should also be checking #expiresAt and #notBefore if they are present in your token
println(decoded.issuer) // "test-issuer"
println(decoded.audience) // ["test"]
// etc

// Non-standard claims are available under #unknownClaims

```

### JSON Web Keys / Key Sets
```kotlin
val keySetData: String = "{...}"//load key set json from source
val keySet = JsonWebKeySet.decodeFromString(keySetData)

val decoded: JWTPayload = JWT.validate(token) { header ->
    keySet.find { it.keyId == header.keyId }!!
}
```