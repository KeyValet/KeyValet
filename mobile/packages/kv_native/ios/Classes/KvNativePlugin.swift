import DeviceCheck
import Flutter
import UIKit
import UserNotifications

public final class KvNativePlugin: NSObject, FlutterPlugin {
    public static var token: String?
    public static var initialApproval: String?
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "dev.keyvalet/kv_native", binaryMessenger: registrar.messenger())
        registrar.addMethodCallDelegate(KvNativePlugin(), channel: channel)
    }
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "initialize":
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try NativeRuntime.boot()
                    DispatchQueue.main.async {
                        NativeRuntime.setForeground(UIApplication.shared.applicationState == .active)
                        UIApplication.shared.registerForRemoteNotifications()
                        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
                        result(nil)
                    }
                } catch { DispatchQueue.main.async { result(FlutterError(code: "hardware_unavailable", message: "Hardware security is unavailable", details: nil)) } }
            }
        case "pushToken": result(Self.token)
        case "initialApprovalId":
            let identifier = Self.initialApproval; Self.initialApproval = nil; result(identifier)
        case "clearNotifications":
            UNUserNotificationCenter.current().removeAllDeliveredNotifications()
            UNUserNotificationCenter.current().removeAllPendingNotificationRequests()
            result(nil)
        case "refreshNotifications":
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let plans = try NativeRuntime.call(["op": "notifications"]) as? [[String: Any]] ?? []
                    let waiting = Set(plans.filter { $0["cancel"] as? Bool != true }.compactMap { $0["approval_id"] as? String })
                    let center = UNUserNotificationCenter.current()
                    center.getDeliveredNotifications { delivered in
                        for notification in delivered {
                            let id = notification.request.content.threadIdentifier
                            guard !id.isEmpty else { continue }
                            if !waiting.contains(id) {
                                center.removeDeliveredNotifications(withIdentifiers: [notification.request.identifier])
                            } else if let plan = plans.first(where: { $0["approval_id"] as? String == id }),
                                plan["banner"] as? Bool == true,
                                notification.request.content.interruptionLevel == .passive,
                                let content = notification.request.content.mutableCopy() as? UNMutableNotificationContent {
                                content.interruptionLevel = .timeSensitive
                                content.sound = .default
                                center.removeDeliveredNotifications(withIdentifiers: [notification.request.identifier])
                                center.add(UNNotificationRequest(identifier: notification.request.identifier, content: content, trigger: nil))
                            }
                        }
                    }
                } catch { }
                DispatchQueue.main.async { result(nil) }
            }
        default: result(FlutterMethodNotImplemented)
        }
    }

    /// Native caller supplies the relay challenge. Attestation bytes never pass through Dart.
    public static func attest(_ challengeHash: Data, completion: @escaping (Data?, Error?) -> Void) {
        let service = DCAppAttestService.shared
        guard service.isSupported else { completion(nil, NativeFailure.unavailable); return }
        service.generateKey { key, error in
            guard let key = key else { completion(nil, error); return }
            service.attestKey(key, clientDataHash: challengeHash, completionHandler: completion)
        }
    }
}
