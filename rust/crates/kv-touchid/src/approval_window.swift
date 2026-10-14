import AppKit
import SwiftUI

private struct ApprovalRow: Decodable {
    let label: String
    let value: String
    let red: Bool
    let secondary: Bool
    let detail: Bool?
}

private struct ApprovalScope: Decodable {
    let label: String
    let allow_label: String
}

private struct ApprovalHeights: Equatable {
    var body: CGFloat = 0
    var footer: CGFloat = 0
}

private struct ApprovalHeightKey: PreferenceKey {
    static var defaultValue: ApprovalHeights { ApprovalHeights() }
    static func reduce(value: inout ApprovalHeights, nextValue: () -> ApprovalHeights) {
        let next = nextValue()
        value.body = max(value.body, next.body)
        value.footer = max(value.footer, next.footer)
    }
}

private struct ApprovalModel: Decodable {
    let kind: String
    let title: String
    let summary: String
    let heading: String?
    let subtitle: String?
    let request_target: String?
    let rows: [ApprovalRow]?
    let scopes: [ApprovalScope]?
    let selected: Int?
    let scope_label: String?
    let allow_label: String?
    let deny_label: String
    let reason_placeholder: String?
    let reason_label: String?
    let details_label: String?
    let label: String?
    let title_red: Bool?

    var valid: Bool {
        guard ["approval", "pairing", "confirmation", "global_grant"].contains(kind),
              !title.isEmpty, !deny_label.isEmpty else { return false }
        if kind == "approval" {
            guard let scopes, !scopes.isEmpty,
                  scopes.indices.contains(selected ?? 0) else { return false }
        } else if allow_label?.isEmpty != false { return false }
        return kind != "confirmation" || label?.isEmpty == false
    }
}

@MainActor
private final class ApprovalState: ObservableObject {
    let model: ApprovalModel
    let preview: Bool
    let maximumHeight: CGFloat
    @Published var selected: Int
    @Published var typed = ""
    @Published var detailsExpanded = false
    @Published var reasonExpanded = false
    @Published private var measuredHeight: CGFloat?
    var resize: (() -> Void)?
    var complete: ((String) -> Void)?
    var decision = "cancel"
    var finished = false

    init(_ model: ApprovalModel, preview: Bool, maximumHeight: CGFloat) {
        self.model = model
        self.preview = preview
        self.maximumHeight = maximumHeight
        selected = model.selected ?? 0
    }

    var primaryRows: [ApprovalRow] {
        (model.rows ?? []).filter { $0.detail != true || $0.red }
    }
    var detailRows: [ApprovalRow] {
        (model.rows ?? []).filter { $0.detail == true && !$0.red }
    }
    var allowLabel: String {
        if let scopes = model.scopes, scopes.indices.contains(selected) {
            return scopes[selected].allow_label
        }
        return model.allow_label ?? ""
    }
    var canAllow: Bool {
        model.kind != "confirmation"
            || typed.utf8.elementsEqual((model.label ?? "").utf8)
    }

    var windowHeight: CGFloat {
        min(maximumHeight, max(240, measuredHeight ?? 360))
    }

    func fit(_ heights: ApprovalHeights) {
        guard heights.body > 0, heights.footer > 0 else { return }
        let height = ceil(heights.body + heights.footer + 1)
        guard measuredHeight != height else { return }
        measuredHeight = height
        resize?()
    }

    func finish(_ value: String) {
        guard !finished, value != "allow" || canAllow else { return }
        finished = true
        decision = preview ? "cancel" : value
        complete?(decision)
    }

    var reply: [String: Any] {
        if model.kind == "approval" {
            return ["decision": decision, "selected": selected, "reason": typed]
        }
        return ["confirmed": decision == "allow", "text": typed]
    }
}

private struct ApprovalRows: View {
    let rows: [ApprovalRow]
    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.offset) { index, row in
                if index > 0 { Divider() }
                HStack(alignment: .top, spacing: 10) {
                    Text(row.label)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .frame(width: 78, alignment: .leading)
                    Text(row.value)
                        .font(.system(size: 13))
                        .foregroundStyle(row.red ? Color.red : row.secondary ? Color.secondary : Color.primary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                .padding(.vertical, 6)
            }
        }
        .padding(.horizontal, 10)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color(nsColor: .separatorColor).opacity(0.35)))
    }
}

private struct ApprovalWindowView: View {
    @ObservedObject var state: ApprovalState
    private var model: ApprovalModel { state.model }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(alignment: .center, spacing: 10) {
                        Image(systemName: model.kind == "pairing" ? "link" : "key.horizontal.fill")
                            .font(.system(size: 17, weight: .medium))
                            .foregroundStyle(.white)
                            .frame(width: 32, height: 32)
                            .background(model.title_red == true ? Color.red : Color.accentColor,
                                        in: RoundedRectangle(cornerRadius: 8))
                        VStack(alignment: .leading, spacing: 3) {
                            Text(model.heading ?? model.title)
                                .font(.system(size: 16, weight: .semibold))
                                .foregroundStyle(model.title_red == true ? Color.red : Color.primary)
                                .fixedSize(horizontal: false, vertical: true)
                            if model.heading != nil {
                                Text(model.subtitle ?? model.title)
                                    .font(.system(size: 12))
                                    .foregroundStyle(model.title_red == true ? Color.red : Color.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    VStack(alignment: .leading, spacing: 5) {
                        Text(model.request_target ?? model.summary)
                            .font(model.kind == "pairing"
                                  ? .system(size: 28, weight: .semibold, design: .monospaced)
                                  : model.kind == "approval"
                                  ? .system(size: 13, weight: .medium, design: .monospaced)
                                  : .system(size: 13))
                            .tracking(model.kind == "pairing" ? 5 : 0)
                            .foregroundStyle(model.title_red == true ? Color.red : Color.primary)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: model.kind == "pairing" ? .center : .leading)
                        if let target = model.request_target, target != model.summary {
                            Text(model.summary).font(.system(size: 12)).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                        }
                    }
                    .padding(10)
                    .background(Color(nsColor: .controlBackgroundColor).opacity(0.6),
                                in: RoundedRectangle(cornerRadius: 7))
                    if !state.primaryRows.isEmpty { ApprovalRows(rows: state.primaryRows) }
                    if let scopes = model.scopes, !scopes.isEmpty {
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text(model.scope_label ?? "").font(.system(size: 12)).foregroundStyle(.secondary)
                            Spacer(minLength: 8)
                            if scopes.count == 1 {
                                Text(scopes[0].label).font(.system(size: 13))
                            } else {
                                Picker(model.scope_label ?? "", selection: $state.selected) {
                                    ForEach(scopes.indices, id: \.self) { index in
                                        Text(scopes[index].label).tag(index)
                                    }
                                }
                                .labelsHidden()
                                .frame(maxWidth: 280)
                            }
                        }
                    }
                    if !state.detailRows.isEmpty || (model.reason_placeholder != nil && !state.reasonExpanded) {
                        HStack(spacing: 12) {
                            if !state.detailRows.isEmpty {
                                Button { state.detailsExpanded.toggle() } label: {
                                    HStack(spacing: 5) {
                                        Image(systemName: "chevron.right")
                                            .font(.system(size: 9, weight: .semibold))
                                            .rotationEffect(.degrees(state.detailsExpanded ? 90 : 0))
                                        Text(model.details_label ?? "")
                                    }
                                }
                                .accessibilityValue(state.detailsExpanded ? "expanded" : "collapsed")
                            }
                            Spacer(minLength: 8)
                            if model.reason_placeholder != nil && !state.reasonExpanded {
                                Button(model.reason_label ?? "") { state.reasonExpanded = true }
                            }
                        }
                        .font(.system(size: 12))
                        .buttonStyle(.plain)
                        .foregroundStyle(.secondary)
                    }
                    if state.detailsExpanded { ApprovalRows(rows: state.detailRows) }
                    if let placeholder = model.reason_placeholder, state.reasonExpanded {
                        TextField(placeholder, text: $state.typed)
                            .textFieldStyle(.roundedBorder)
                            .onChange(of: state.typed) { value in
                                if value.count > 512 { state.typed = String(value.prefix(512)) }
                            }
                    }
                    if model.kind == "confirmation" {
                        TextField(model.label ?? "", text: $state.typed)
                            .textFieldStyle(.roundedBorder)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(18)
                .background(GeometryReader { geometry in
                    Color.clear.preference(key: ApprovalHeightKey.self,
                        value: ApprovalHeights(body: geometry.size.height))
                })
            }
            .scrollIndicators(.hidden)
            Divider()
            HStack(spacing: 8) {
                Spacer()
                Button(model.deny_label) { state.finish(model.kind == "approval" ? "deny" : "cancel") }
                    .buttonStyle(.bordered)
                Button(state.allowLabel) { state.finish("allow") }
                    .buttonStyle(.borderedProminent)
                    .disabled(!state.canAllow)
            }
            .controlSize(.regular)
            .padding(.horizontal, 18)
            .padding(.vertical, 11)
            .background(GeometryReader { geometry in
                Color.clear.preference(key: ApprovalHeightKey.self,
                    value: ApprovalHeights(footer: geometry.size.height))
            })
        }
        .frame(width: 440, height: state.windowHeight)
        .background(Color(nsColor: .windowBackgroundColor))
        .onPreferenceChange(ApprovalHeightKey.self) { state.fit($0) }
        .onExitCommand { state.finish("cancel") }
    }
}

@MainActor
private final class ApprovalWindowController: NSObject, NSWindowDelegate {
    let state: ApprovalState
    let window: NSPanel
    var captured: Bool

    init(model: ApprovalModel, preview: Bool) {
        let maximumHeight = max(240, (NSScreen.main?.visibleFrame.height ?? 800) - 90)
        state = ApprovalState(model, preview: preview, maximumHeight: maximumHeight)
        captured = !preview
        window = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 440, height: state.windowHeight),
            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        super.init()
        window.title = "KeyValet"
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.delegate = self
        window.contentView = NSHostingView(rootView: ApprovalWindowView(state: state))
        window.defaultButtonCell = nil
        window.center()
        state.resize = { [weak self] in
            guard let self else { return }
            self.window.setContentSize(NSSize(width: 440, height: self.state.windowHeight))
        }
        state.complete = { [weak self] _ in
            self?.window.orderOut(nil)
            NSApplication.shared.stopModal()
        }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        state.finish("cancel")
        return false
    }

    func capture(to path: String) {
        guard let view = window.contentView else { return }
        view.layoutSubtreeIfNeeded()
        window.displayIfNeeded()
        guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.effectiveAppearance.performAsCurrentDrawingAppearance {
            view.cacheDisplay(in: view.bounds, to: bitmap)
        }
        if let png = bitmap.representation(using: .png, properties: [:]) {
            do { try png.write(to: URL(fileURLWithPath: path)); captured = true } catch { }
        }
    }
}

// CONTRACT: this bridge receives only the Rust presentation allowlist, never signing material.
@_cdecl("kv_remote_dialog")
public func remoteDialog(
    _ input: UnsafePointer<UInt8>, _ inputLength: Int,
    _ output: UnsafeMutablePointer<UInt8>, _ outputLength: UnsafeMutablePointer<Int>,
    _ previewPath: UnsafePointer<UInt8>, _ previewLength: Int
) -> Int32 {
    guard Thread.isMainThread, inputLength <= 131072,
          let model = try? JSONDecoder().decode(ApprovalModel.self, from: Data(bytes: input, count: inputLength)),
          model.valid else { return -50 }
    return MainActor.assumeIsolated {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let controller = ApprovalWindowController(model: model, preview: previewLength > 0)
        if previewLength > 0 {
            controller.window.appearance = NSAppearance(named:
                ProcessInfo.processInfo.environment["KEYVALET_UI_PREVIEW_APPEARANCE"] == "dark" ? .darkAqua : .aqua)
        }
        let escape = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            if event.keyCode == 53 {
                controller.state.finish("cancel")
                return nil
            }
            return event
        }
        defer { if let escape { NSEvent.removeMonitor(escape) } }
        let timeout = Timer.scheduledTimer(withTimeInterval: 120, repeats: false) { _ in
            MainActor.assumeIsolated { controller.state.finish("cancel") }
        }
        RunLoop.current.add(timeout, forMode: .modalPanel)
        defer { timeout.invalidate() }
        var captureTimer: Timer?
        if previewLength > 0 {
            let path = String(decoding: UnsafeBufferPointer(start: previewPath, count: previewLength), as: UTF8.self)
            captureTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: false) { _ in
                MainActor.assumeIsolated {
                    controller.capture(to: path)
                    controller.state.finish("cancel")
                }
            }
            if let captureTimer { RunLoop.current.add(captureTimer, forMode: .modalPanel) }
        }
        defer { captureTimer?.invalidate() }
        application.activate(ignoringOtherApps: true)
        application.runModal(for: controller.window)
        controller.window.orderOut(nil)
        guard controller.captured else { return -1 }
        guard let data = try? JSONSerialization.data(withJSONObject: controller.state.reply),
              data.count <= outputLength.pointee else { return -50 }
        data.copyBytes(to: output, count: data.count)
        outputLength.pointee = data.count
        return 0
    }
}
