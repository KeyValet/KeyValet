import CryptoKit
import Foundation
import LocalAuthentication
import Security

// Private key representations crossing this boundary are encrypted and device-bound; the
// derived AES key goes to the root parent in memory. A fresh LAContext and the key's ACL
// enforce authentication for each subprocess, rather than a separate boolean check.
@_cdecl("kv_enclave_key")
public func enclaveKey(
    _ create: Int32,
    _ blob: UnsafePointer<UInt8>, _ blobLength: Int,
    _ peer: UnsafePointer<UInt8>, _ peerLength: Int,
    _ reason: UnsafePointer<CChar>, _ cancel: UnsafePointer<CChar>,
    _ outputBlob: UnsafeMutablePointer<UInt8>, _ outputBlobLength: UnsafeMutablePointer<Int>,
    _ outputPeer: UnsafeMutablePointer<UInt8>, _ outputKey: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard SecureEnclave.isAvailable else { return -25291 }
    let context = LAContext()
    context.localizedReason = String(cString: reason)
    context.localizedCancelTitle = String(cString: cancel)
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer { context.invalidate() }
    do {
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        let publicPeer: P256.KeyAgreement.PublicKey
        if create != 0 {
            var error: Unmanaged<CFError>?
            guard let acl = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence], &error
            ) else { return -50 }
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: acl, authenticationContext: context)
            // The software private half is never serialized or retained beyond this expression.
            publicPeer = P256.KeyAgreement.PrivateKey().publicKey
        } else {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: Data(bytes: blob, count: blobLength),
                authenticationContext: context)
            publicPeer = try P256.KeyAgreement.PublicKey(
                x963Representation: Data(bytes: peer, count: peerLength))
        }
        let secret = try key.sharedSecretFromKeyAgreement(with: publicPeer)
        let derived = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(),
            sharedInfo: Data("keyvalet/master-key/v1".utf8), outputByteCount: 32)
        let representation = key.dataRepresentation
        guard representation.count <= outputBlobLength.pointee else { return -50 }
        representation.copyBytes(to: outputBlob, count: representation.count)
        outputBlobLength.pointee = representation.count
        publicPeer.x963Representation.copyBytes(to: outputPeer, count: 65)
        derived.withUnsafeBytes { bytes in
            outputKey.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }
        return 0
    } catch {
        // Never serialize CryptoKit errors or key representations to logs.
        let code = (error as NSError).code
        return code == 0 ? -1 : Int32(clamping: code)
    }
}

// Fixed failure tags preserve typed facts without returning localized system error text.
private func remoteKeyFailureStatus(_ error: Error) -> Int32 {
    var current = error as NSError
    for _ in 0..<8 {
        if current.domain == LAError.errorDomain {
            switch current.code {
            case -2, -3, -4, -9: return -100001
            case -1, -8: return -100002
            default: break
            }
        } else if current.domain == NSOSStatusErrorDomain {
            if current.code == Int(errSecUserCanceled) { return -100001 }
            if current.code == Int(errSecAuthFailed) { return -100002 }
        }
        guard let underlying = current.userInfo[NSUnderlyingErrorKey] as? NSError else { break }
        current = underlying
    }
    return -100003
}

// Remote identity and approval keys use separate objects and ACLs from the vault key.
@_cdecl("kv_device_key")
public func deviceKey(
    _ operation: Int32, _ role: Int32,
    _ blob: UnsafePointer<UInt8>, _ blobLength: Int,
    _ input: UnsafePointer<UInt8>, _ inputLength: Int,
    _ outputBlob: UnsafeMutablePointer<UInt8>, _ outputBlobLength: UnsafeMutablePointer<Int>,
    _ outputPublic: UnsafeMutablePointer<UInt8>,
    _ outputData: UnsafeMutablePointer<UInt8>, _ outputDataLength: UnsafeMutablePointer<Int>
) -> Int32 {
    guard SecureEnclave.isAvailable, (0...2).contains(role) else { return -25291 }
    let context = LAContext()
    context.localizedReason = "Approve the KeyValet remote request"
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer { context.invalidate() }
    do {
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        if operation == 0 {
            let accessibility = role == 0
                ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let flags: SecAccessControlCreateFlags = role == 2
                ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
            var error: Unmanaged<CFError>?
            guard let acl = SecAccessControlCreateWithFlags(nil, accessibility, flags, &error)
                else { return -50 }
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: acl, authenticationContext: context)
        } else {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: Data(bytes: blob, count: blobLength),
                authenticationContext: context)
        }
        key.publicKey.x963Representation.copyBytes(to: outputPublic, count: 65)
        let representation = key.dataRepresentation
        guard representation.count <= outputBlobLength.pointee else { return -50 }
        representation.copyBytes(to: outputBlob, count: representation.count)
        outputBlobLength.pointee = representation.count
        switch operation {
        case 0:
            outputDataLength.pointee = 0
        case 1:
            let signing = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: representation, authenticationContext: context)
            let signature = try signing.signature(for: Data(bytes: input, count: inputLength))
            guard outputDataLength.pointee >= 64 else { return -50 }
            signature.rawRepresentation.copyBytes(to: outputData, count: 64)
            outputDataLength.pointee = 64
        case 2:
            let peer = try P256.KeyAgreement.PublicKey(
                x963Representation: Data(bytes: input, count: inputLength))
            let secret = try key.sharedSecretFromKeyAgreement(with: peer)
            guard outputDataLength.pointee >= 32 else { return -50 }
            secret.withUnsafeBytes {
                outputData.update(from: $0.bindMemory(to: UInt8.self).baseAddress!, count: 32)
            }
            outputDataLength.pointee = 32
        default:
            return -50
        }
        return 0
    } catch {
        return remoteKeyFailureStatus(error)
    }
}
