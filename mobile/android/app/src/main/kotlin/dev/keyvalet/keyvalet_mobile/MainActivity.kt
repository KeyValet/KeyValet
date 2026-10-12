package dev.keyvalet.keyvalet_mobile
import android.content.Intent
import io.flutter.embedding.android.FlutterFragmentActivity
import dev.keyvalet.nativebridge.NativeRuntime
class MainActivity : FlutterFragmentActivity() {
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); setIntent(intent) }
    override fun onResume() { super.onResume(); NativeRuntime.foreground(this) }
    override fun onPause() { NativeRuntime.foreground(null); super.onPause() }
}
