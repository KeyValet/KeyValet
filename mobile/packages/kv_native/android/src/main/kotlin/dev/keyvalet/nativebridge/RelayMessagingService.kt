package dev.keyvalet.nativebridge

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.json.JSONArray
import org.json.JSONObject

class RelayMessagingService: FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        getSharedPreferences("kv_push", Context.MODE_PRIVATE).edit().putString("token", token).apply()
        try { NativeRuntime.call(this, JSONObject().put("op", "push_token").put("platform", "fcm").put("token", token)) } catch (_: Exception) { }
    }
    override fun onMessageReceived(message: RemoteMessage) {
        // Push fields are only a wake-up hint. Trusted mode/body/actions come from Rust.
        try { val updates = NativeRuntime.call(this, JSONObject().put("op", "sync")) as JSONArray
            for (index in 0 until updates.length()) Notifications.show(this, updates.getJSONObject(index))
        } catch (_: Exception) { }
    }
}
object Notifications {
    fun show(context: Context, view: JSONObject) {
        val manager = context.getSystemService(NotificationManager::class.java)
        val id = view.getString("approval_id"); val numericId = id.hashCode()
        if (view.getBoolean("cancel")) { manager.cancel(id, numericId); return }
        manager.createNotificationChannel(NotificationChannel("kv_silent", context.getString(R.string.kv_silent), NotificationManager.IMPORTANCE_LOW).apply { setSound(null, null); enableVibration(false) })
        manager.createNotificationChannel(NotificationChannel("kv_banner", context.getString(R.string.kv_banner), NotificationManager.IMPORTANCE_HIGH))
        val app = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return
        app.putExtra("approval_id", id)
        val open = PendingIntent.getActivity(context, numericId, app, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(context, if (view.getBoolean("banner")) "kv_banner" else "kv_silent")
            .setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle(view.getString("title")).setContentText(view.getString("body"))
            .setStyle(Notification.BigTextStyle().bigText(view.getString("body"))).setContentIntent(open).setAutoCancel(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE).setGroup(id).setTimeoutAfter((view.getLong("expires_at")*1000-System.currentTimeMillis()).coerceAtLeast(1))
        if (view.getBoolean("quick_allowed")) {
            for (allow in listOf(true, false)) {
                val intent = Intent(context, QuickApprovalService::class.java).putExtra("approval_id", id).putExtra("allow", allow)
                val action = PendingIntent.getForegroundService(context, numericId*2+if (allow) 1 else 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                notification.addAction(Notification.Action.Builder(null, context.getString(if (allow) R.string.kv_allow else R.string.kv_deny), action).setAuthenticationRequired(true).build())
            }
        } else notification.addAction(Notification.Action.Builder(null, context.getString(R.string.kv_open), open).build())
        try { manager.notify(id, numericId, notification.build()) } catch (_: SecurityException) { }
    }
}
