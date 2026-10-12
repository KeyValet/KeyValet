package dev.keyvalet.nativebridge

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Every strong signature authenticates the actual Signature CryptoObject. No Boolean gate. */
class HardwareKeys(private val context: Context) {
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    @Volatile var activity: FragmentActivity? = null
    var keyKind: String = "tee"
        private set
    @Synchronized fun initialize() {
        for (slot in 0..2) {
            val alias = "keyvalet_$slot"
            if (!store.containsAlias(alias)) {
                try { create(alias, slot, true) }
                catch (_: StrongBoxUnavailableException) { create(alias, slot, false) }
            }
            val key = store.getKey(alias, null) as PrivateKey
            val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
            check(info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT || info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX) { "Hardware-backed keys required" }
            if (slot == 0) keyKind = if (info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX) "strongbox" else "tee"
            if (slot == 2) check(info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds == 0)
        }
    }
    private fun create(alias: String, slot: Int, strongBox: Boolean) {
        val purposes = KeyProperties.PURPOSE_SIGN or if (slot == 0) KeyProperties.PURPOSE_AGREE_KEY else 0
        val builder = KeyGenParameterSpec.Builder(alias, purposes).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256).setIsStrongBoxBacked(strongBox)
        if (slot == 1) builder.setUnlockedDeviceRequired(true)
        if (slot == 2) builder.setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG).setInvalidatedByBiometricEnrollment(true)
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(builder.build()); generateKeyPair() }
    }
    fun publicKey(slot: Int): ByteArray {
        val key = store.getCertificate("keyvalet_$slot").publicKey as java.security.interfaces.ECPublicKey
        fun coordinate(number: java.math.BigInteger) = number.toByteArray().let { value -> ByteArray(32).also { out -> val count = minOf(32, value.size); value.copyInto(out, 32-count, value.size-count) } }
        return byteArrayOf(4) + coordinate(key.w.affineX) + coordinate(key.w.affineY)
    }
    fun sign(slot: Int, message: ByteArray, authenticate: Boolean = true): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(store.getKey("keyvalet_$slot", null) as PrivateKey)
        if (slot == 2 && authenticate) authenticate(signature)
        // A tampered caller skipping authenticate still fails here in AndroidKeyStore.
        signature.update(message)
        return rawSignature(signature.sign())
    }
    private fun authenticate(signature: Signature) {
        check(Looper.myLooper() != Looper.getMainLooper())
        val owner = activity ?: throw SecurityException("Open app required")
        val completed = CountDownLatch(1)
        var authorized: Signature? = null
        Handler(Looper.getMainLooper()).post {
            val prompt = BiometricPrompt(owner, { task -> Handler(Looper.getMainLooper()).post(task) }, object: BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { authorized = result.cryptoObject?.signature; completed.countDown() }
                override fun onAuthenticationError(code: Int, message: CharSequence) { completed.countDown() }
            })
            prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(context.getString(R.string.kv_authorize))
                .setNegativeButtonText(context.getString(R.string.kv_cancel)).setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG).build(), BiometricPrompt.CryptoObject(signature))
        }
        if (!completed.await(60, TimeUnit.SECONDS) || authorized !== signature) throw SecurityException("Biometric signing denied")
    }
    fun ecdh(point: ByteArray): ByteArray {
        require(point.size == 65 && point[0] == 4.toByte())
        // ASN.1 SubjectPublicKeyInfo prefix for id-ecPublicKey / prime256v1.
        val prefix = byteArrayOf(0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x02,0x01,0x06,0x08,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x03,0x01,0x07,0x03,0x42,0)
        val peer = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(prefix + point))
        return KeyAgreement.getInstance("ECDH", "AndroidKeyStore").apply { init(store.getKey("keyvalet_0", null)); doPhase(peer, true) }.generateSecret().also { check(it.size == 32) }
    }
    private fun rawSignature(der: ByteArray): ByteArray {
        require(der.size in 8..72 && der[0] == 0x30.toByte() && der[1].toInt() == der.size-2)
        var offset = 2
        val output = ByteArray(64)
        for (part in 0..1) {
            require(offset + 2 <= der.size && der[offset++] == 2.toByte())
            val length = der[offset++].toInt() and 255
            require(length in 1..33 && offset+length <= der.size)
            require((der[offset].toInt() and 128) == 0)
            val skip = if (der[offset] == 0.toByte() && length > 1) 1 else 0
            require(length - skip <= 32)
            if (skip == 1) require((der[offset + 1].toInt() and 128) != 0)
            der.copyInto(output, part*32+32-(length-skip), offset+skip, offset+length); offset += length
        }
        require(offset == der.size); return output
    }
}
