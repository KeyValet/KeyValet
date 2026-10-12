import CryptoKit
import Foundation
import LocalAuthentication
import Security
import AppKit

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

// CONTRACT: §6.3 / §9.2: this boundary receives only the Rust presentation allowlist.
@_cdecl("kv_remote_dialog")
public func remoteDialog(
    _ input: UnsafePointer<UInt8>, _ inputLength: Int,
    _ output: UnsafeMutablePointer<UInt8>, _ outputLength: UnsafeMutablePointer<Int>,
    _ previewPath: UnsafePointer<UInt8>, _ previewLength: Int
) -> Int32 {
    guard Thread.isMainThread, inputLength <= 131072,
          let model = try? JSONSerialization.jsonObject(with: Data(bytes: input, count: inputLength)) as? [String: Any],
          let title = model["title"] as? String, let summary = model["summary"] as? String
        else { return -50 }
    let application = NSApplication.shared
    application.setActivationPolicy(.accessory)
    let alert = NSAlert()
    if previewLength > 0 {
        alert.window.appearance = NSAppearance(named: .aqua)
    }
    alert.messageText = title
    alert.alertStyle = .informational
    let scopes = model["scopes"] as? [[String: String]] ?? []
    let selected = model["selected"] as? Int ?? 0
    let allow = alert.addButton(withTitle: scopes.indices.contains(selected)
        ? scopes[selected]["allow_label"] ?? "" : model["allow_label"] as? String ?? "")
    let deny = alert.addButton(withTitle: model["deny_label"] as? String ?? "")
    allow.keyEquivalent = ""
    deny.keyEquivalent = ""
    // CONTRACT: §6.9 / D10: Escape leaves the approval pending rather than signing a denial.
    let escapeMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
        if event.keyCode == 53 {
            application.abortModal()
            alert.window.orderOut(nil)
            return nil
        }
        return event
    }
    defer { if let monitor = escapeMonitor { NSEvent.removeMonitor(monitor) } }
    let stack = NSStackView()
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 9
    if model["title_red"] as? Bool == true {
        alert.messageText = ""
        let warningTitle = NSTextField(wrappingLabelWithString: title)
        warningTitle.font = .systemFont(ofSize: 14, weight: .semibold)
        warningTitle.textColor = .systemRed
        warningTitle.preferredMaxLayoutWidth = 620
        stack.addArrangedSubview(warningTitle)
    }
    let header = NSTextField(wrappingLabelWithString: summary)
    header.font = .systemFont(ofSize: 22, weight: .semibold)
    header.textColor = model["title_red"] as? Bool == true ? .systemRed : .labelColor
    header.preferredMaxLayoutWidth = 620
    stack.addArrangedSubview(header)
    for row in model["rows"] as? [[String: Any]] ?? [] {
        let label = row["label"] as? String ?? ""
        let value = row["value"] as? String ?? ""
        let field = NSTextField(wrappingLabelWithString: "\(label)   \(value)")
        let secondary = row["secondary"] as? Bool == true
        field.font = .systemFont(ofSize: secondary ? 12 : 13)
        field.textColor = row["red"] as? Bool == true ? .systemRed
            : secondary ? .secondaryLabelColor : .labelColor
        field.preferredMaxLayoutWidth = 620
        stack.addArrangedSubview(field)
    }
    var popup: NSPopUpButton?
    if !scopes.isEmpty {
        let field = NSTextField(labelWithString: model["scope_label"] as? String ?? "")
        stack.addArrangedSubview(field)
        let menu = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 620, height: 28), pullsDown: false)
        menu.addItems(withTitles: scopes.map { $0["label"] ?? "" })
        if scopes.indices.contains(selected) { menu.selectItem(at: selected) }
        stack.addArrangedSubview(menu)
        popup = menu
    }
    var editor: NSTextField?
    if let placeholder = model["reason_placeholder"] as? String {
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 620, height: 26))
        field.placeholderString = placeholder
        field.maximumNumberOfLines = 1
        stack.addArrangedSubview(field)
        editor = field
    } else if model["kind"] as? String == "confirmation" {
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 620, height: 26))
        field.placeholderString = model["label"] as? String
        stack.addArrangedSubview(field)
        editor = field
        allow.isEnabled = false
    }
    for view in stack.arrangedSubviews {
        view.translatesAutoresizingMaskIntoConstraints = false
        view.widthAnchor.constraint(equalToConstant: 620).isActive = true
    }
    stack.frame = NSRect(x: 0, y: 0, width: 620, height: stack.fittingSize.height)
    alert.accessoryView = stack
    alert.window.title = "KeyValet"
    alert.window.level = .floating
    let started = Date()
    var timedOut = false
    let timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { _ in
        if let menu = popup, scopes.indices.contains(menu.indexOfSelectedItem) {
            allow.title = scopes[menu.indexOfSelectedItem]["allow_label"] ?? ""
        }
        if model["kind"] as? String == "confirmation" {
            allow.isEnabled = editor?.stringValue == model["label"] as? String
        }
        if Date().timeIntervalSince(started) >= 120 {
            timedOut = true
            application.abortModal()
            alert.window.orderOut(nil)
        }
    }
    RunLoop.current.add(timer, forMode: .modalPanel)
    defer { timer.invalidate() }
    var captured = previewLength == 0
    if previewLength > 0 {
        let path = String(decoding: UnsafeBufferPointer(start: previewPath, count: previewLength), as: UTF8.self)
        let capture = Timer.scheduledTimer(withTimeInterval: 1, repeats: false) { _ in
            if let view = alert.window.contentView,
               let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
                view.effectiveAppearance.performAsCurrentDrawingAppearance {
                    view.cacheDisplay(in: view.bounds, to: bitmap)
                    if let opaque = NSBitmapImageRep(bitmapDataPlanes: nil,
                        pixelsWide: bitmap.pixelsWide, pixelsHigh: bitmap.pixelsHigh,
                        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                        isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
                       let context = NSGraphicsContext(bitmapImageRep: opaque) {
                        NSGraphicsContext.saveGraphicsState()
                        NSGraphicsContext.current = context
                        let bounds = NSRect(x: 0, y: 0, width: bitmap.pixelsWide, height: bitmap.pixelsHigh)
                        NSColor.white.setFill()
                        bounds.fill()
                        bitmap.draw(in: bounds, from: .zero, operation: .sourceOver,
                            fraction: 1, respectFlipped: false, hints: nil)
                        NSGraphicsContext.restoreGraphicsState()
                        if let png = opaque.representation(using: .png, properties: [:]) {
                            do { try png.write(to: URL(fileURLWithPath: path)); captured = true } catch { }
                        }
                    }
                }
            }
            application.abortModal()
            alert.window.orderOut(nil)
        }
        RunLoop.current.add(capture, forMode: .modalPanel)
    }
    application.activate(ignoringOtherApps: true)
    let response = alert.runModal()
    guard captured else { return -1 }
    let labelConfirmed = model["kind"] as? String != "confirmation"
        || editor?.stringValue == model["label"] as? String
    let approved = previewLength == 0 && !timedOut && labelConfirmed && response == .alertFirstButtonReturn
    let result: [String: Any]
    if model["kind"] as? String == "approval" {
        result = ["decision": approved ? "allow"
            : previewLength == 0 && !timedOut && response == .alertSecondButtonReturn ? "deny" : "cancel",
            "selected": popup?.indexOfSelectedItem ?? 0, "reason": editor?.stringValue ?? ""]
    } else {
        result = ["confirmed": approved, "text": editor?.stringValue ?? ""]
    }
    guard let data = try? JSONSerialization.data(withJSONObject: result), data.count <= outputLength.pointee
        else { return -50 }
    data.copyBytes(to: output, count: data.count)
    outputLength.pointee = data.count
    return 0
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
        let code = (error as NSError).code
        return code == 0 ? -1 : Int32(clamping: code)
    }
}
