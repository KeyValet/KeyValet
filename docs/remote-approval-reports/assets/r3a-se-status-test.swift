import Foundation
import Security
import LocalAuthentication
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


var cases = 0
func check(_ error: NSError, _ expected: Int32) {
    precondition(remoteKeyFailureStatus(error) == expected, "typed NSError classification mismatch")
    cases += 1
}
for code in [LAError.Code.userCancel, .userFallback, .systemCancel, .appCancel] {
    check(NSError(domain: LAError.errorDomain, code: code.rawValue), -100001)
}
check(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecUserCanceled)), -100001)
for code in [LAError.Code.authenticationFailed, .biometryLockout] {
    check(NSError(domain: LAError.errorDomain, code: code.rawValue), -100002)
}
check(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecAuthFailed)), -100002)
check(NSError(domain: "org.keyvalet.fixture", code: -2), -100003)
check(NSError(domain: NSOSStatusErrorDomain, code: -2), -100003)
let cancelled = NSError(domain: LAError.errorDomain, code: LAError.Code.userCancel.rawValue)
check(NSError(domain: NSCocoaErrorDomain, code: 99, userInfo: [NSUnderlyingErrorKey: cancelled]), -100001)
var deep: NSError = cancelled
for _ in 0..<8 { deep = NSError(domain: NSCocoaErrorDomain, code: 99, userInfo: [NSUnderlyingErrorKey: deep]) }
check(deep, -100003)
print("NSError classification cases passed: \(cases); authentication/key operations: 0")
