import CryptoKit
import XCTest
import LocalAuthentication
@testable import kv_native

final class StrongSigningGateTests: XCTestCase {
    func testTamperedUICannotSignStrongWithoutBiometry() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("Physical Secure Enclave and provisioned App Group required; Simulator does not prove hardware authentication")
        #else
        guard SecureEnclave.isAvailable else { throw XCTSkip("Requires a real Secure Enclave device with biometric enrollment and App Group provisioning") }
        var biometricError: NSError?
        guard LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &biometricError) else {
            throw XCTSkip("Enroll biometrics before running the physical signing-gate test")
        }
        let store = try KeyStore()
        _ = try store.publicKey(2)
        let probe = Data("quick-positive-control".utf8)
        let quickSignature = try P256.Signing.ECDSASignature(rawRepresentation: store.sign(1, message: probe))
        XCTAssertTrue(try P256.Signing.PublicKey(x963Representation: store.publicKey(1)).isValidSignature(quickSignature, for: probe))
        // Call the actual signer directly, bypassing the Flutter UI and all Boolean state.
        XCTAssertThrowsError(try store.sign(2, message: Data("tampered-ui".utf8), withoutInteraction: true))
        #endif
    }
    func testIdentityBlobSupportsSigningAndECDH() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("Physical Secure Enclave and provisioned App Group required; Simulator does not prove hardware authentication")
        #else
        guard SecureEnclave.isAvailable else { throw XCTSkip("Secure Enclave is unavailable in Simulator") }
        let store = try KeyStore()
        let publicPoint = try store.publicKey(0)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: store.sign(0, message: Data("dk-probe".utf8)))
        XCTAssertTrue(try P256.Signing.PublicKey(x963Representation: publicPoint).isValidSignature(signature, for: Data("dk-probe".utf8)))
        XCTAssertEqual(try store.ecdh(publicPoint).count, 32)
        #endif
    }
}
