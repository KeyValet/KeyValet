package dev.keyvalet.nativebridge

import android.content.Context
import org.json.JSONObject

/** Shared by the Flutter plugin and FCM workers. No Dart isolate is started. */
object NativeRuntime {
    private var keys: HardwareKeys? = null
    private var ready = false
    init { System.loadLibrary("kv_mobile_core"); System.loadLibrary("kv_native") }
    @JvmStatic private external fun nativeOpen(config: String): String
    @JvmStatic private external fun nativeCall(command: String): String
    @Synchronized fun boot(context: Context) {
        if (ready) return
        val hardware = HardwareKeys(context.applicationContext).apply { initialize() }
        keys = hardware
        val config = JSONObject().put("directory", context.noBackupFilesDir.resolve("core").absolutePath)
            .put("label", "Android").put("os", "android").put("key_kind", hardware.keyKind)
        check(JSONObject(nativeOpen(config.toString())).getBoolean("ok")) { "Hardware security unavailable" }
        ready = true
    }
    fun foreground(activity: androidx.fragment.app.FragmentActivity?) { keys?.activity = activity }
    @JvmStatic fun keyOperation(slot: Int, operation: Int, input: ByteArray): ByteArray? {
        if (slot !in 0..2 || input.size > 128*1024) return null
        return try { val store = keys ?: return null
            when (operation) {0 -> store.publicKey(slot); 1 -> store.sign(slot, input); 2 -> if (slot == 0) store.ecdh(input) else null; else -> null}
        } catch (_: Exception) { null }
    }
    fun call(context: Context, command: JSONObject): Any {
        boot(context)
        val response = JSONObject(nativeCall(command.toString()))
        check(response.getBoolean("ok")) { response.optString("error", "native_unavailable") }
        return response.get("result")
    }
}
