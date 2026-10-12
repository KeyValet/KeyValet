import CryptoKit
import Foundation
import Darwin
import LocalAuthentication
import Security

enum NativeFailure: Error { case unavailable, invalidKey, locked, authenticationRequired }

/// No software fallback. Opaque Secure Enclave representations are device-bound, never raw keys.
public final class KeyStore {
    static let appGroup = "group.dev.keyvalet.mobile"
    private let container: URL
    private let creationLock = NSLock()
    public var allowStrong = false

    public init() throws {
        guard SecureEnclave.isAvailable,
              let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroup) else {
            throw NativeFailure.unavailable
        }
        self.container = container
    }

    private func acl(_ slot: Int) throws -> SecAccessControl {
        let protection = slot == 0 ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let flags: SecAccessControlCreateFlags = slot == 2 ? [.privateKeyUsage, .biometryCurrentSet] : [.privateKeyUsage]
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, protection, flags, &error) else {
            if let error = error { throw error.takeRetainedValue() }
            throw NativeFailure.invalidKey
        }
        return control
    }

    private func identity() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        creationLock.lock(); defer { creationLock.unlock() }
        let descriptor = open(container.appendingPathComponent("identity.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw NativeFailure.unavailable }
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw NativeFailure.unavailable }
        defer { flock(descriptor, LOCK_UN) }
        let path = container.appendingPathComponent("dk.sealed")
        if FileManager.default.fileExists(atPath: path.path) {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(contentsOf: path))
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl(0))
        try key.dataRepresentation.write(to: path, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        return key
    }

    private func approvalBlob(_ slot: Int) throws -> Data {
        creationLock.lock(); defer { creationLock.unlock() }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "dev.keyvalet.approval.keys", kSecAttrAccount as String: "ak_\(slot)",
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let blob = result as? Data { return blob }
        guard status == errSecItemNotFound else { throw NativeFailure.locked }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: acl(slot))
        var attributes = query
        attributes.removeValue(forKey: kSecReturnData as String)
        attributes.removeValue(forKey: kSecMatchLimit as String)
        attributes[kSecValueData as String] = key.dataRepresentation
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        attributes[kSecAttrSynchronizable as String] = false
        guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else { throw NativeFailure.invalidKey }
        return key.dataRepresentation
    }

    public func publicKey(_ slot: Int) throws -> Data {
        if slot == 0 { return try identity().publicKey.x963Representation }
        let cache = container.appendingPathComponent("ak_\(slot).public")
        // NSE has no approval keychain access. Only public points cross the App Group boundary.
        if Bundle.main.bundleURL.pathExtension == "appex" {
            let data = try Data(contentsOf: cache)
            guard data.count == 65 && data.first == 4 else { throw NativeFailure.invalidKey }
            return data
        }
        // Cold background launches can occur while locked. The main App, like
        // NSE, needs only cached approval public points to boot Rust's store.
        let blob: Data
        do { blob = try approvalBlob(slot) }
        catch NativeFailure.locked {
            let data = try Data(contentsOf: cache)
            guard data.count == 65 && data.first == 4 else { throw NativeFailure.invalidKey }
            return data
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        let publicPoint = key.publicKey.x963Representation
        try publicPoint.write(to: cache, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        return publicPoint
    }

    public func sign(_ slot: Int, message: Data, withoutInteraction: Bool = false) throws -> Data {
        if slot == 0 {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: identity().dataRepresentation)
            return try key.signature(for: message).rawRepresentation
        }
        if slot == 2 && !allowStrong && !withoutInteraction { throw NativeFailure.authenticationRequired }
        let context = LAContext()
        context.localizedReason = NSLocalizedString("Authorize KeyValet", comment: "Biometric signing prompt")
        context.interactionNotAllowed = withoutInteraction
        // The actual private-key operation enforces biometryCurrentSet. No Boolean auth result.
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: approvalBlob(slot), authenticationContext: context)
        return try key.signature(for: message).rawRepresentation
    }

    public func ecdh(_ peer: Data) throws -> Data {
        let point = try P256.KeyAgreement.PublicKey(x963Representation: peer)
        let secret = try identity().sharedSecretFromKeyAgreement(with: point)
        return secret.withUnsafeBytes { Data($0) }
    }
}
