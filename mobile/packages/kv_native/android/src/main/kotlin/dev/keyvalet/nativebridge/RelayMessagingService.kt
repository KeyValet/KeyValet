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
        PushSyncJob.enqueue(this, false)
    }
    override fun onMessageReceived(message: RemoteMessage) {
        // Push fields are only a wake-up hint. Trusted mode/body/actions come from Rust.
        val data = message.data
        val id = data["approval_id"] ?: return
        if (id.length != 26 || id.any { it !in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" } || id[0] > '7'
            || data.keys.any { it !in setOf("approval_id", "delivery.mode", "to") }
            || data["delivery.mode"] !in setOf("silent", "banner") || data["to"].isNullOrEmpty()) return
        // Fetching/authenticating can exceed the Firebase callback's few seconds.
        // JobScheduler keeps the native/Rust worker alive without a Flutter engine.
        PushSyncJob.enqueue(this, message.priority == RemoteMessage.PRIORITY_HIGH)
    }
    override fun onDeletedMessages() { PushSyncJob.enqueue(this, false) }
}
object Notifications {
    fun clear(context: Context) { context.getSystemService(NotificationManager::class.java).cancelAll() }
    fun refresh(context: Context) {
        try { val updates = NativeRuntime.call(context, JSONObject().put("op", "notifications")) as JSONArray
            val manager = context.getSystemService(NotificationManager::class.java)
            val waiting = mutableSetOf<String>()
            for (index in 0 until updates.length()) {
                val view = updates.getJSONObject(index)
                if (!view.getBoolean("cancel")) waiting.add(view.getString("approval_id"))
                show(context, view)
            }
            for (active in manager.activeNotifications) {
                if (active.tag != null && active.tag !in waiting) manager.cancel(active.tag, active.id)
            }
        } catch (error: IllegalStateException) {
            if (error.message == "login_required") clear(context)
        }
    }
    fun show(context: Context, view: JSONObject) {
        val manager = context.getSystemService(NotificationManager::class.java)
        val id = view.getString("approval_id"); val numericId = id.hashCode()
        if (view.getBoolean("cancel")) { manager.cancel(id, numericId); return }
        manager.createNotificationChannel(NotificationChannel("kv_silent", context.getString(R.string.kv_silent), NotificationManager.IMPORTANCE_LOW).apply { setSound(null, null); enableVibration(false) })
        manager.createNotificationChannel(NotificationChannel("kv_banner", context.getString(R.string.kv_banner), NotificationManager.IMPORTANCE_HIGH).apply {
            setSound(android.provider.Settings.System.DEFAULT_NOTIFICATION_URI,
                android.media.AudioAttributes.Builder().setUsage(android.media.AudioAttributes.USAGE_NOTIFICATION).build())
            enableVibration(true)
        })
        val channel = if (view.getBoolean("banner")) "kv_banner" else "kv_silent"
        val previous = manager.activeNotifications.firstOrNull { it.tag == id && it.id == numericId }
        // Android notification channels are immutable. Repost on escalation using
        // the same tag/id so there is one approval notification, with audible upgrade.
        if (previous != null && previous.notification.channelId != channel) manager.cancel(id, numericId)
        val app = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return
        app.putExtra("approval_id", id).setData(android.net.Uri.parse("keyvalet://approval/$id/open"))
        val open = PendingIntent.getActivity(context, numericId, app, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(context, channel)
            .setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle(view.getString("title")).setContentText(view.getString("body"))
            .setStyle(Notification.BigTextStyle().bigText(view.getString("body"))).setContentIntent(open).setAutoCancel(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE).setGroup(id).setOnlyAlertOnce(previous?.notification?.channelId == channel)
            .setCategory(Notification.CATEGORY_RECOMMENDATION).setTimeoutAfter((view.getLong("expires_at")*1000-System.currentTimeMillis()).coerceAtLeast(1))
        if (view.getBoolean("quick_allowed")) {
            for (allow in listOf(true, false)) {
                val intent = Intent(context, QuickApprovalService::class.java).putExtra("approval_id", id).putExtra("allow", allow)
                    .setData(android.net.Uri.parse("keyvalet://approval/$id/${if (allow) "allow" else "deny"}"))
                val action = PendingIntent.getForegroundService(context, numericId*2+if (allow) 1 else 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                notification.addAction(Notification.Action.Builder(null, context.getString(if (allow) R.string.kv_allow else R.string.kv_deny), action).setAuthenticationRequired(true).build())
            }
        } else notification.addAction(Notification.Action.Builder(null, context.getString(R.string.kv_open), open).build())
        try { manager.notify(id, numericId, notification.build()) } catch (_: SecurityException) { }
    }
}
