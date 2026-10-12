import Foundation
import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
    private let completionLock = NSLock()
    private var completion: ((UNNotificationContent) -> Void)?
    private var fallback: UNNotificationContent?

    override func didReceive(_ request: UNNotificationRequest, withContentHandler handler: @escaping (UNNotificationContent) -> Void) {
        completion = handler
        let content = request.content.mutableCopy() as! UNMutableNotificationContent
        // The push contains only routing metadata. Never trust its mode or claimed approval level.
        content.title = "KeyValet"
        content.body = NSLocalizedString("Open KeyValet to review", comment: "Safe notification fallback")
        content.sound = nil
        content.interruptionLevel = .passive
        content.categoryIdentifier = ""
        fallback = content
        guard let approvalID = content.userInfo["approval_id"] as? String else { finish(content); return }
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let notifications = try NativeRuntime.call(["op": "sync"]) as? [[String: Any]] ?? []
                guard let model = notifications.last(where: { $0["approval_id"] as? String == approvalID }) else { self.finish(content); return }
                if model["cancel"] as? Bool == true {
                    UNUserNotificationCenter.current().getDeliveredNotifications { delivered in
                        let ids = delivered.filter { $0.request.content.threadIdentifier == approvalID }.map { $0.request.identifier }
                        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: ids)
                    }
                    content.body = NSLocalizedString("Approval no longer waiting", comment: "Cancelled notification")
                    self.finish(content); return
                }
                content.title = model["title"] as? String ?? "KeyValet"
                content.body = model["body"] as? String ?? content.body
                content.threadIdentifier = approvalID
                let banner = model["banner"] as? Bool == true
                content.interruptionLevel = banner ? .timeSensitive : .passive
                content.sound = banner ? .default : nil
                content.categoryIdentifier = model["quick_allowed"] as? Bool == true ? "KEYVALET_QUICK" : "KEYVALET_STRONG"
                UNUserNotificationCenter.current().getDeliveredNotifications { delivered in
                    let prior = delivered.filter { $0.request.content.threadIdentifier == approvalID }.map { $0.request.identifier }
                    UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: prior)
                    self.finish(content)
                }
            } catch { self.finish(content) }
        }
    }
    override func serviceExtensionTimeWillExpire() { if let content = fallback { finish(content) } }
    private func finish(_ content: UNNotificationContent) {
        completionLock.lock()
        let handler = completion; completion = nil
        completionLock.unlock()
        handler?(content)
    }
}
