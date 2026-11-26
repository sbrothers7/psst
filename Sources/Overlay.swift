import AppKit

/// A view that lets clicks through to what's under it (the menu bar icon's dot).
final class Dot: NSView { override func hitTest(_ point: NSPoint) -> NSView? { nil } }

// MARK: - Overlay

final class Panel: NSPanel {
    var canKey = true
    override var canBecomeKey: Bool { canKey }

    convenience init(_ rect: NSRect) {
        self.init(contentRect: rect, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        isOpaque = false
        backgroundColor = .clear
        hasShadow = false
        hidesOnDeactivate = false
        isReleasedWhenClosed = false
        level = .statusBar
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary, .ignoresCycle]
        appearance = NSAppearance(named: .darkAqua)
    }

    /// A menu bar app has no Edit menu, so ⌘Q and the edit shortcuts are wired by hand.
    override func performKeyEquivalent(with e: NSEvent) -> Bool {
        let keys: [String: Selector] = [
            "q": #selector(NSApplication.terminate(_:)), "x": #selector(NSText.cut(_:)), "c": #selector(NSText.copy(_:)),
            "v": #selector(NSText.paste(_:)), "a": #selector(NSText.selectAll(_:)), "z": Selector(("undo:")),
        ]
        if e.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command,
           let sel = keys[e.charactersIgnoringModifiers ?? ""], NSApp.sendAction(sel, to: nil, from: self) { return true }
        return super.performKeyEquivalent(with: e)
    }
}

/// Blurred bubble. Dragging it moves the overlay unless locked; right-click shows its menu.
final class Flipped: NSView { override var isFlipped: Bool { true } }  // top-down scroll content
final class Row: NSView { var ts = 0.0 }  // a feed row, kept in time order
let barWidth: CGFloat = 380  // the chat bar, and the feed column above it

final class Bubble: NSVisualEffectView {
    override func acceptsFirstMouse(for e: NSEvent?) -> Bool { true }
    override func hitTest(_ p: NSPoint) -> NSView? {
        guard let v = super.hitTest(p) else { return nil }
        return v is NSTextView || (v as? NSTextField)?.isEditable == true ? v : self  // the typing area keeps its clicks
    }
    override func mouseDown(with e: NSEvent) {
        if !UserDefaults.standard.bool(forKey: "locked") { window?.performDrag(with: e) }
    }
}

func pill(_ content: NSView) -> Bubble {
    let v = Bubble()
    v.material = .hudWindow
    v.blendingMode = .behindWindow
    v.state = .active
    v.wantsLayer = true
    v.layer?.cornerRadius = 9
    v.layer?.masksToBounds = true
    content.translatesAutoresizingMaskIntoConstraints = false
    v.addSubview(content)
    NSLayoutConstraint.activate([
        content.leadingAnchor.constraint(equalTo: v.leadingAnchor, constant: 10),
        content.trailingAnchor.constraint(equalTo: v.trailingAnchor, constant: -10),
        content.topAnchor.constraint(equalTo: v.topAnchor, constant: 5),
        content.bottomAnchor.constraint(equalTo: v.bottomAnchor, constant: -5),
    ])
    return v
}

/// /ping: the edges of every screen glow in the accent color, three times, with who pinged at the top.
/// Click-through, over everything.
func flashEdges(_ text: String) {
    for screen in NSScreen.screens {
        let w = NSWindow(contentRect: screen.frame, styleMask: .borderless, backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        w.isOpaque = false
        w.backgroundColor = .clear
        w.ignoresMouseEvents = true
        w.level = .screenSaver
        w.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        w.contentView = pingView(text, top: screen.frame.maxY - screen.visibleFrame.maxY + 16)  // below the menu bar
        w.alphaValue = 0
        w.orderFrontRegardless()
        func pulse(_ left: Int) {
            NSAnimationContext.runAnimationGroup({ $0.duration = 0.2; w.animator().alphaValue = 1 }) {
                NSAnimationContext.runAnimationGroup({ $0.duration = 0.35; w.animator().alphaValue = 0 }) { left > 1 ? pulse(left - 1) : w.close() }
            }
        }
        pulse(3)
    }
}

/// The accent border and, `top` points down, a tag saying who pinged.
func pingView(_ text: String, top: CGFloat) -> NSView {
    let v = NSView(), tag = NSView(), label = NSTextField(labelWithString: text)
    v.wantsLayer = true
    v.layer?.borderWidth = 8
    v.layer?.borderColor = NSColor.controlAccentColor.cgColor
    tag.wantsLayer = true
    tag.layer?.backgroundColor = NSColor.controlAccentColor.cgColor
    tag.layer?.cornerRadius = 12
    label.font = .boldSystemFont(ofSize: 22)
    label.textColor = .white
    for x in [tag, label] { x.translatesAutoresizingMaskIntoConstraints = false }
    tag.addSubview(label)
    v.addSubview(tag)
    NSLayoutConstraint.activate([
        label.leadingAnchor.constraint(equalTo: tag.leadingAnchor, constant: 18),
        label.trailingAnchor.constraint(equalTo: tag.trailingAnchor, constant: -18),
        label.topAnchor.constraint(equalTo: tag.topAnchor, constant: 8),
        label.bottomAnchor.constraint(equalTo: tag.bottomAnchor, constant: -8),
        tag.centerXAnchor.constraint(equalTo: v.centerXAnchor),
        tag.topAnchor.constraint(equalTo: v.topAnchor, constant: top),
    ])
    return v
}
