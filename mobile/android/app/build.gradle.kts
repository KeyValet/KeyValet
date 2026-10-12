plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "dev.keyvalet.keyvalet_mobile"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "dev.keyvalet.mobile"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = 31
        targetSdk = 36
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        create("production") {
            val keyPath = System.getenv("KV_ANDROID_KEYSTORE")
            if (keyPath != null) {
                storeFile = file(keyPath)
                storePassword = System.getenv("KV_ANDROID_STORE_PASSWORD")
                keyAlias = System.getenv("KV_ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("KV_ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // Production signing material is supplied by the packaging environment.
            signingConfig = signingConfigs.getByName("production")
        }
    }
}

if (file("google-services.json").exists()) { apply(plugin = "com.google.gms.google-services") }

flutter {
    source = "../.."
}
