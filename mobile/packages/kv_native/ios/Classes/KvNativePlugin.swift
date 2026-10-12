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
