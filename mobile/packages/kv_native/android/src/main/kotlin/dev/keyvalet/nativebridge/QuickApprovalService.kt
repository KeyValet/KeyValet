package dev.keyvalet.nativebridge

import android.app.Service
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.KeyguardManager
import android.content.Intent
import android.os.IBinder
import org.json.JSONObject
import java.util.concurrent.Executors

class QuickApprovalService: Service() {
    private val worker = Executors.newSingleThreadExecutor()
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("kv_worker", getString(R.string.kv_worker), NotificationManager.IMPORTANCE_LOW))
        startForeground(9408, Notification.Builder(this, "kv_worker").setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle(getString(R.string.kv_worker)).build())
        worker.execute {
            try {
                check(!getSystemService(KeyguardManager::class.java).isDeviceLocked)
                val id = intent?.getStringExtra("approval_id") ?: error("Missing approval")
                NativeRuntime.call(this, JSONObject().put("op", "quick_decision").put("approval_id", id).put("allow", intent.getBooleanExtra("allow", false)))
                manager.cancel(id, id.hashCode())
            } catch (_: Exception) { }
            finally { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(startId) }
        }
        return START_NOT_STICKY
    }
    override fun onDestroy() { worker.shutdown(); super.onDestroy() }
}
