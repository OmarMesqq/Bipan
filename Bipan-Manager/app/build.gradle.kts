plugins {
    // Defaults
    alias(libs.plugins.android.application)
    // Compose plugin
    alias(libs.plugins.compose.compiler)
    // Kotlin Symbol Processing
    id("com.google.devtools.ksp")
}

android {
    namespace = "org.omarmesqq.bipanmanager"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "org.omarmesqq.bipanmanager"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        ndk {
            //noinspection ChromeOsAbiSupport
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            optimization {
                enable = true
                keepRules {
                    includeDefault = false
                }
            }

            ndk {
                debugSymbolLevel = "SYMBOL_TABLE"
            }

            externalNativeBuild {
                cmake {
                    arguments += "-DCMAKE_BUILD_TYPE=Release"
                }
            }

            signingConfig = signingConfigs.getByName("debug")
        }

        debug {
            ndk {
                debugSymbolLevel = "FULL"
            }
            externalNativeBuild {
                cmake {
                    arguments += "-DCMAKE_BUILD_TYPE=Debug"
                }
            }
        }

        create("debugLeakCanary") {
            // Copies all default debugging configurations from the built-in debug type
            initWith(getByName("debug"))

            // Matching fallbacks ensure libraries that only know about 'debug' work here too
            matchingFallbacks += listOf("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    externalNativeBuild {
        cmake {
            path("src/main/native/CMakeLists.txt")
        }
    }
}


dependencies {
    // Defaults
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.core.ktx)

    // Compose plugin
    implementation(platform(libs.androidx.compose.bom))

    // Custom
    implementation(libs.androidx.core.splashscreen)
    implementation(libs.androidx.datastore.preferences)

    // Compose app
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)

    // Navbar
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.compose.material.icons.extended)

    // Root access
    implementation(libs.libsu)

    // Android is dying...
    implementation(libs.freeDroidWarn)

    // SQLite abstraction layer
    implementation(libs.androidx.room3.runtime)
    ksp(libs.androidx.room3.compiler)

    "debugLeakCanaryImplementation"(libs.leakcanary.android)
}