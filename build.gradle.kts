plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "co.screenmate.can.agent"
    compileSdk = 34

    // Present at runtime inside the stock app's process (privileged, holds CAR_VENDOR_EXTENSION).
    useLibrary("android.car")

    defaultConfig {
        applicationId = "co.screenmate.can.agent"
        minSdk = 34
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
    }
    buildTypes { release { isMinifyEnabled = false } }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(project(":common"))
}
