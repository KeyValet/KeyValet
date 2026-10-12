import CryptoKit
import Foundation
import Security

// Run from an unlocked macOS GUI terminal; all keys are disposable and never serialized.
do {
    guard SecureEnclave.isAvailable else { throw NSError(domain: "W1", code: 1) }
    var error: Unmanaged<CFError>?
    guard let acl = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], &error
    ) else { throw NSError(domain: "W1", code: 2) }
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl)
    let suite = HPKE.Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
    let info = Data("keyvalet/envelope/v1".utf8)
    let aad = Data("disposable W1 spike".utf8)
    let plaintext = Data("public test message".utf8)
    var sender = try HPKE.Sender(recipientKey: key.publicKey, ciphersuite: suite, info: info)
    let ciphertext = try sender.seal(plaintext, authenticating: aad)
    var recipient = try HPKE.Recipient(
        privateKey: key, ciphersuite: suite, info: info, encapsulatedKey: sender.encapsulatedKey)
    guard try recipient.open(ciphertext, authenticating: aad) == plaintext else {
        throw NSError(domain: "W1", code: 3)
    }
    print("hpke_recipient=pass")
    let peer = P256.KeyAgreement.PrivateKey()
    let secret = try key.sharedSecretFromKeyAgreement(with: peer.publicKey)
    let reference = try peer.sharedSecretFromKeyAgreement(with: key.publicKey)
    guard secret.withUnsafeBytes({ Data($0) }) == reference.withUnsafeBytes({ Data($0) }) else {
        throw NSError(domain: "W1", code: 4)
    }
    print("raw_ecdh=pass length=32")
    let signing = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: key.dataRepresentation)
    let signature = try signing.signature(for: plaintext)
    let publicKey = try P256.Signing.PublicKey(x963Representation: key.publicKey.x963Representation)
    guard publicKey.isValidSignature(signature, for: plaintext) else {
        throw NSError(domain: "W1", code: 5)
    }
    print("same_key_es256=pass signature_length=64")
} catch {
    print("spike_failed code=\((error as NSError).code)")
    exit(1)
}
