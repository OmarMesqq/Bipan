// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    // Defaults
    alias(libs.plugins.android.application) apply false
    // Compose plugin
    alias(libs.plugins.compose.compiler) apply false
    // Kotlin Symbol Processing
    id("com.google.devtools.ksp") version "2.3.11" apply false
}