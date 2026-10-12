import Flutter
import UIKit
import UserNotifications
import kv_native

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    let allow = UNNotificationAction(identifier: "KV_ALLOW", title: NSLocalizedString("Allow once", comment: "Quick action"), options: [.authenticationRequired])
    let deny = UNNotificationAction(identifier: "KV_DENY", title: NSLocalizedString("Deny", comment: "Quick action"), options: [.authenticationRequired])
    let open = UNNotificationAction(identifier: "KV_OPEN", title: NSLocalizedString("Open app to approve", comment: "Strong action"), options: [.foreground, .authenticationRequired])
    UNUserNotificationCenter.current().setNotificationCategories([
      UNNotificationCategory(identifier: "KEYVALET_QUICK", actions: [allow, deny], intentIdentifiers: [], options: []),
      UNNotificationCategory(identifier: "KEYVALET_STRONG", actions: [open], intentIdentifiers: [], options: [])])
    UNUserNotificationCenter.current().delegate = self
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  override func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken token: Data) {
    let value = token.map { String(format: "%02x", $0) }.joined()
    KvNativePlugin.token = value
    DispatchQueue.global().async { _ = try? NativeRuntime.call(["op": "push_token", "platform": "apns", "token": value]) }
  }
  override func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
    let identifier = response.notification.request.content.threadIdentifier
    guard !identifier.isEmpty else { completionHandler(); return }
    if response.actionIdentifier == "KV_ALLOW" || response.actionIdentifier == "KV_DENY" {
      DispatchQueue.global(qos: .userInitiated).async {
        // UNNotificationAction forces unlock; AK_q's key accessibility enforces it again.
        do { _ = try NativeRuntime.call(["op": "quick_decision", "approval_id": identifier, "allow": response.actionIdentifier == "KV_ALLOW"])
          center.removeDeliveredNotifications(withIdentifiers: [response.notification.request.identifier])
        } catch { }
        completionHandler()
      }
    } else {
      KvNativePlugin.initialApproval = identifier
      completionHandler()
    }
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
  }
}
