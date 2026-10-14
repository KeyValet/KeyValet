package dev.keyvalet.nativebridge

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.fragment.app.FragmentActivity
import com.google.firebase.messaging.FirebaseMessaging
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.Executors
import org.json.JSONObject

class KvNativePlugin: FlutterPlugin, MethodChannel.MethodCallHandler, ActivityAware {
    private lateinit var context: Context
    private lateinit var channel: MethodChannel
    private val worker = Executors.newSingleThreadExecutor()
    private var activity: FragmentActivity? = null
    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, "dev.keyvalet/kv_native").also { it.setMethodCallHandler(this) }
    }
    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) { channel.setMethodCallHandler(null); worker.shutdown() }
    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "initialize" -> worker.execute {
                try { NativeRuntime.boot(context); NativeRuntime.foreground(activity)
                    Handler(Looper.getMainLooper()).post {
                        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                            activity?.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 9608)
                        }
                        result.success(null)
                    }
                    try { FirebaseMessaging.getInstance().token.addOnSuccessListener { token -> worker.execute { saveToken(token) } } } catch (_: IllegalStateException) { }
                } catch (_: Exception) { Handler(Looper.getMainLooper()).post { result.error("hardware_unavailable", "Hardware security is unavailable", null) } }
            }
            "initialApprovalId" -> {
                val identifier = activity?.intent?.getStringExtra("approval_id")
                activity?.intent?.removeExtra("approval_id")
                result.success(identifier)
            }
            "pushToken" -> result.success(context.getSharedPreferences("kv_push", Context.MODE_PRIVATE).getString("token", null))
            "refreshNotifications" -> worker.execute {
                Notifications.refresh(context)
                Handler(Looper.getMainLooper()).post { result.success(null) }
            }
            "clearNotifications" -> { Notifications.clear(context); result.success(null) }
            else -> result.notImplemented()
        }
    }
    private fun saveToken(token: String) {
        context.getSharedPreferences("kv_push", Context.MODE_PRIVATE).edit().putString("token", token).apply()
        try { NativeRuntime.call(context, JSONObject().put("op", "push_token").put("platform", "fcm").put("token", token).put("force_upload", true)) } catch (_: Exception) { }
        PushSyncJob.enqueue(context, false)
    }
    override fun onAttachedToActivity(binding: ActivityPluginBinding) { activity = binding.activity as? FragmentActivity; NativeRuntime.foreground(activity) }
    override fun onDetachedFromActivity() { activity = null; NativeRuntime.foreground(null) }
    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = onAttachedToActivity(binding)
}
