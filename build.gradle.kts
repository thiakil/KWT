plugins {
    kotlin("multiplatform") version "2.0.21"
    kotlin("plugin.serialization") version "2.1.0"
}

group = "com.thiakil"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

val serialization_version: String by project.extra
val ktor_version: String by project.extra

kotlin {
    applyDefaultHierarchyTemplate()
    explicitApi()

    jvm()
    //js() {
    //    nodejs()
    //}
    //mingwX64()
    //linuxX64()
    //linuxArm64()

    jvmToolchain(21)

    sourceSets {
        commonMain {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:$serialization_version")
                implementation("org.jetbrains.kotlinx:kotlinx-io-core:0.6.0")
                implementation("io.ktor:ktor-utils:$ktor_version")
            }
        }
        commonTest {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}