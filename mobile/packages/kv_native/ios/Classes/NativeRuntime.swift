import Foundation

/// Shared with KeyValetNSE; this file neither imports nor starts Flutter.
public enum NativeRuntime {
    private static let lock = NSLock()
    private static var keys: KeyStore?
    private static var ready = false
    private static let callback: KvKeyCallback = { slot, operation, input, inputSize, output, capacity in
        do {
            guard let keys = keys, let output = output else { return -1 }
            let bytes = input.map { Data(bytes: $0, count: inputSize) } ?? Data()
            let result: Data
            switch operation {
            case 0: result = try keys.publicKey(Int(slot))
            case 1: result = try keys.sign(Int(slot), message: bytes)
            case 2:
                guard slot == 0 else { return -1 }
                result = try keys.ecdh(bytes)
            default: return -1
            }
            guard result.count <= capacity else { return -1 }
            result.copyBytes(to: output, count: result.count)
            return result.count
        } catch { return -1 }
    }

    public static func boot() throws {
        lock.lock(); defer { lock.unlock() }
        if ready { return }
        let store = try KeyStore()
        guard let directory = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: KeyStore.appGroup) else {
            throw NativeFailure.unavailable
        }
        // Populate only public caches before the extension is ever woken.
        for slot in 0...2 { _ = try store.publicKey(slot) }
        keys = store
        let config: [String: Any] = ["directory": directory.appendingPathComponent("core").path,
            "label": "iPhone", "os": "ios", "key_kind": "secure_enclave"]
        let result = try consume(JSONSerialization.data(withJSONObject: config)) { kv_mobile_open($0, callback) }
        guard result["ok"] as? Bool == true else { keys = nil; throw NativeFailure.unavailable }
        ready = true
    }

    public static func setForeground(_ foreground: Bool) { keys?.allowStrong = foreground }
    public static func call(_ command: [String: Any]) throws -> Any {
        try boot()
        let response = try consume(JSONSerialization.data(withJSONObject: command)) { kv_mobile_call($0) }
        guard response["ok"] as? Bool == true, let result = response["result"] else { throw NativeFailure.unavailable }
        return result
    }
    private static func consume(_ bytes: Data, operation: (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?) throws -> [String: Any] {
        guard let input = String(data: bytes, encoding: .utf8) else { throw NativeFailure.invalidKey }
        return try input.withCString { pointer in
            guard let output = operation(pointer) else { throw NativeFailure.unavailable }
            defer { kv_mobile_free(output) }
            let data = Data(String(cString: output).utf8)
            guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NativeFailure.unavailable }
            return result
        }
    }
}
