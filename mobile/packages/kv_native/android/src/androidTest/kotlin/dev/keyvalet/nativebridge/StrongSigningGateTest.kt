package dev.keyvalet.nativebridge

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.Assert.fail
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.json.JSONObject

class StrongSigningGateTest {
    @Test fun nativeWorkerLoadsRustAndRequiresAccountBeforeSnapshot() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val manager = androidx.biometric.BiometricManager.from(context)
        assumeTrue("Physical hardware and enrolled strong biometrics required", manager.canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS)
        // Exercise the packaged ELF dependencies, JNI callback, hardware DK ECDH and Rust
        // database initialization. A compiler-host DT_NEEDED path must fail this probe.
        val account = NativeRuntime.call(context, JSONObject().put("op", "account_status")) as JSONObject
        assertTrue(!account.getBoolean("signed_in"))
        assertTrue(!account.has("keys") && !account.has("session_token") && !account.has("envelope"))
        try { NativeRuntime.call(context, JSONObject().put("op", "snapshot")); fail("Snapshot bypassed account sign-in") }
        catch (expected: IllegalStateException) { assertTrue(expected.message?.contains("login_required") == true) }
    }
    @Test fun tamperedUiCannotSignWithoutCryptoObjectAuthentication() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val manager = androidx.biometric.BiometricManager.from(context)
        assumeTrue("Physical hardware and enrolled strong biometrics required", manager.canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS)
        val keys = HardwareKeys(context)
        keys.initialize() // Unexpected provisioning failures must fail on eligible hardware.
        try { keys.sign(2, "tampered UI bypass".toByteArray(), authenticate = false); fail("Strong signature bypassed key authentication") }
        catch (expected: java.security.GeneralSecurityException) { /* AndroidKeyStore denied the private-key operation. */ }
    }
}
