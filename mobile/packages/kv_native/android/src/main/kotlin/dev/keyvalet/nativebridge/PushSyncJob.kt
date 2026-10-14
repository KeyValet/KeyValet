package dev.keyvalet.nativebridge

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Durable native-only inbox and token reconciliation; API 31+ requires no new dependency. */
class PushSyncJob : JobService() {
    private val worker = Executors.newSingleThreadExecutor()
    private val stopped = AtomicBoolean(false)

    override fun onStartJob(params: JobParameters): Boolean {
        stopped.set(false)
        worker.execute {
            var retry = false
            try {
                val token = getSharedPreferences("kv_push", Context.MODE_PRIVATE).getString("token", null)
                if (token != null) NativeRuntime.call(this,
                    JSONObject().put("op", "push_token").put("platform", "fcm").put("token", token))
                val response = NativeRuntime.call(this, JSONObject().put("op", "background_sync")) as JSONObject
                val views = response.getJSONArray("notifications")
                retry = response.getBoolean("retry")
                if (!stopped.get()) {
                    for (index in 0 until views.length()) Notifications.show(this, views.getJSONObject(index))
                    Notifications.refresh(this)
                    Log.i("KeyValetPush", "event=sync_complete plans=${views.length()} retry=$retry")
                }
            } catch (error: Exception) {
                val signedOut = error is IllegalStateException && error.message == "login_required"
                if (signedOut) Notifications.clear(this)
                retry = !signedOut
                // Only known static Rust error codes; never arbitrary exception messages.
                val reason = (error as? IllegalStateException)?.message?.takeIf {
                    it in setOf("login_required", "network_unavailable", "rate_limited", "relay_unavailable",
                        "authentication_failed", "invalid_session", "invalid_challenge", "hardware_unavailable",
                        "storage_busy", "storage_integrity", "relay_rejected", "relay_protocol")
                } ?: "native_unavailable"
                Log.i("KeyValetPush", "event=${if (signedOut) "signed_out" else "sync_retry"} reason=$reason")
            } finally {
                if (!stopped.get()) jobFinished(params, retry)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean { stopped.set(true); return true }
    override fun onDestroy() { stopped.set(true); worker.shutdown(); super.onDestroy() }

    companion object {
        private const val JOB_ID = 9409
        fun enqueue(context: Context, expedited: Boolean) {
            val scheduler = context.getSystemService(JobScheduler::class.java)
            val component = ComponentName(context, PushSyncJob::class.java)
            if (expedited) {
                val fast = JobInfo.Builder(JOB_ID, component).setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .setExpedited(true).build()
                if (scheduler.schedule(fast) == JobScheduler.RESULT_SUCCESS) return
            }
            val regular = JobInfo.Builder(JOB_ID, component).setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(true).setBackoffCriteria(10_000, JobInfo.BACKOFF_POLICY_EXPONENTIAL).build()
            if (scheduler.schedule(regular) != JobScheduler.RESULT_SUCCESS)
                Log.i("KeyValetPush", "event=schedule_failed")
        }
    }
}
