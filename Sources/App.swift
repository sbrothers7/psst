import AppKit
import Carbon.HIToolbox
import Network

// MARK: - Chat shortcut

/// Carbon modifier mask and label ("⌃⌥Space") for a key press. nil without ⌃ or ⌥: plain or ⌘ keys are other apps' shortcuts.
func hotKeySpec(_ f: NSEvent.ModifierFlags, key: Int, chars: String) -> (mods: Int, label: String)? {
    guard f.contains(.control) || f.contains(.option) else { return nil }
    let on = [(NSEvent.ModifierFlags.control, controlKey, "⌃"), (.option, optionKey, "⌥"), (.shift, shiftKey, "⇧"), (.command, cmdKey, "⌘")]
        .filter { f.contains($0.0) }
    let names = [kVK_Space: "Space", kVK_Return: "↩", kVK_Tab: "⇥", kVK_Delete: "⌫"]  // ponytail: F-keys show as a blank glyph
    return (on.reduce(0) { $0 | $1.1 }, on.map(\.2).joined() + (names[key] ?? chars.uppercased()))
}

// MARK: - Client app

final class App: NSObject, NSApplicationDelegate, NSMenuDelegate, NSTextFieldDelegate, NSWindowDelegate {
    let d = UserDefaults.standard
    var server: Server?
    var line: Line?
    var browser: NWBrowser?
    var hosts: [NWBrowser.Result] = [], attempts = 0
    var fails: [String: Int] = [:], downUntil: [String: Date] = [:], sleptAt: Date?  // see electHost, onWake
    var viaID = "", viaSince = 0.0, dialed = "", hops = 0  // the host this Mac is on, the Mac it dialled, how far
    var prevRoom = "public", lastSeen = 0.0  // to pick up where we were after reconnecting
    var me = "", room = "public", via = "", roster: [String] = [], rooms: Set<String> = [], invited: Set<String> = []
    let status = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    let stack = NSStackView(), field = NSTextField(), hintLabel = NSTextField(wrappingLabelWithString: "")
    let feedDoc = Flipped()
    var seen = Set<String>()  // messages already shown (time + sender), so a replay never repeats one
    var history: Bool { d.bool(forKey: "history") }  // /history on: messages stay and the feed scrolls back
    let grip = NSImageView(), ctx = NSMenu()
    var feed: Panel!, input: Panel!, hints: Panel!
    var suggestions: [Suggestion] = [], pick = 0
    var menu: (source: String, path: [String])?  // open menu: the typed text that lists it, then the rows picked into
    var hotKey: EventHotKeyRef?
    var settings: NSWindow?
    let box = NSStackView(), welcomeText = NSTextField(wrappingLabelWithString: "")
    let tabs = NSTabView(), peopleBox = NSStackView(), aboutBox = NSStackView()  // settings: Profile is `box`
    let peopleScroll = NSScrollView(), peopleNote = NSTextField(labelWithString: "")
    let nameField = NSTextField(), nameNote = NSTextField(wrappingLabelWithString: "")
    let lockBox = NSButton(checkboxWithTitle: "Lock overlay position", target: nil, action: nil)
    let loginBox = NSButton(checkboxWithTitle: "Open Psst at login", target: nil, action: nil)
    let updateBox = NSButton(checkboxWithTitle: "Install automatically, checking", target: nil, action: nil)
    let updateLabel = NSTextField(labelWithString: "Psst \(appVersion)")
    let checkButton = NSButton(title: "Check Now", target: nil, action: nil), updateNowButton = NSButton(title: "Update Now", target: nil, action: nil)
    var latest: String?, updateState: String?  // newest version on GitHub, once looked; what the updater is doing
    let filterBox = NSButton(checkboxWithTitle: "Hide swearing and NSFW words", target: nil, action: nil)
    let typingBox = NSButton(checkboxWithTitle: "Show typing indicators, and share mine", target: nil, action: nil)
    let mentionBox = NSButton(checkboxWithTitle: "Play a sound when someone @mentions me", target: nil, action: nil)
    let pingsBox = NSButton(checkboxWithTitle: "Let people ping me (flashes my screen edges)", target: nil, action: nil)
    let saveButton = NSButton(title: "Save", target: nil, action: nil)
    let shortcutButton = NSButton(title: "", target: nil, action: nil)
    var recorder: Any?  // key monitor while a new shortcut is being typed
    var popups: [NSPopUpButton] = []

    var name: String? { d.string(forKey: "name") }  // nil until picked on first launch
    var myStatus: Int { d.integer(forKey: "status") }  // see statusNames
    var shortcut: String { d.string(forKey: "hotKeyLabel") ?? "⌥Space" }
    var friends: [String] {
        get { d.stringArray(forKey: "friends") ?? [] }
        set { d.set(newValue, forKey: "friends") }
    }
    lazy var identity = loadIdentity()
    lazy var pairing: PairingEditor = { let e = PairingEditor(); e.isFieldEditor = true; return e }()
    var typers: [String: (label: String, until: Date)] = [:]  // "room name" -> who's typing there, until when
    var busy: [String] = []                  // online people in do not disturb
    var typingSentAt = Date.distantPast, typingRow: Row?
    var known: [String: String] = [:]        // name -> latest public key seen from the host
    var members: [String: [String: String]] = [:]  // private room -> member name -> public key
    var changed: [String: String] = [:]      // name -> new key that doesn't match the remembered one
    var openRooms: [String: Int] = [:]       // private rooms on the network -> people in each
    var locked: Set<String> = []             // rooms that take a password
    var roomDescs: [String: String] = [:]    // room -> description
    var roomTypes: [String: Int] = [:]       // room -> who can get in (see typeNames)
    var asks: [String: [Suggestion]] = [:]   // questions asked as a menu: title -> answers
    var roomOwner: [String: String] = [:]    // room -> its creator
    var roomBans: [String: [String]] = [:]   // room -> who its creator banned
    var pics: [String: String] = [:]        // name -> profile picture (see validPic)
    let picPreview = NSImageView()
    var requests: [String: [String]] = [:]   // room -> people asking to join, latest last
    var lastAsked: String?                   // room of the latest request, for a bare /accept elsewhere
    var nicks: [String: [String: String]] = [:]  // room -> name -> nickname there
    var pins: [String: String] {             // name -> key remembered on first sight (trust on first use)
        get { d.dictionary(forKey: "pins") as? [String: String] ?? [:] }
        set { d.set(newValue, forKey: "pins") }
    }
    var blocked: [String] {
        get { d.stringArray(forKey: "blocked") ?? [] }
        set { d.set(newValue, forKey: "blocked") }
    }

    func applicationDidFinishLaunching(_ n: Notification) {
        let f = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 800, height: 600)
        if d.bool(forKey: "invisible") { d.set(2, forKey: "status"); d.removeObject(forKey: "invisible") }  // Psst 1.0 kept a bool
        d.register(defaults: ["cooldown": 10.0, "retention": 600.0, "status": 0, "pings": true, "invites": "everyone",
                              "color": "auto", "picKind": "none", "history": false, "filter": true, "typing": true, "mentionSound": true, "alignMine": "left", "alignOthers": "left", "autoUpdate": true, "updateEvery": 86400.0, "hotKeyCode": kVK_Space, "hotKeyMods": optionKey, "hotKeyLabel": "⌥Space",
                              "x": f.minX + 12, "y": f.minY + 12])
        buildUI()
        registerHotKey()
        if name == nil { showSettings(welcome: true) }  // first launch: pick a username before anything connects
        updateIfDue(launch: true)
        Timer.scheduledTimer(withTimeInterval: 600, repeats: true) { [weak self] _ in self?.updateIfDue() }
        Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in self?.regroup() }
        let ws = NSWorkspace.shared.notificationCenter
        ws.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in self?.sleptAt = Date() }
        ws.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in self?.onWake() }

        let b = NWBrowser(for: .bonjourWithTXTRecord(type: serviceType, domain: nil), using: tcp())
        b.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self else { return }
            self.hosts = Array(results)
            self.regroup()
        }
        b.start(queue: .main)
        browser = b
        startHost()
    }

    func buildUI() {
        status.button?.image = NSImage(systemSymbolName: "bubble.left", accessibilityDescription: "Psst")
        status.button?.appearsDisabled = true
        let menu = NSMenu()
        menu.delegate = self
        status.menu = menu
        ctx.delegate = self  // right-click menu on the overlay, filled in menuNeedsUpdate

        feed = Panel(NSRect(x: 0, y: 0, width: barWidth, height: 1))  // a column over the chat bar; mine on its right
        feed.canKey = false
        feed.delegate = self
        feed.acceptsMouseMovedEvents = true
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        feedDoc.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: feedDoc.leadingAnchor),
            stack.topAnchor.constraint(equalTo: feedDoc.topAnchor),
            stack.widthAnchor.constraint(equalToConstant: barWidth),
        ])
        let scroll = NSScrollView(frame: feed.contentView!.bounds)  // scrolls back once /history is on
        scroll.autoresizingMask = [.width, .height]
        scroll.drawsBackground = false
        scroll.contentView.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.scrollerStyle = .overlay
        scroll.verticalScrollElasticity = .none
        scroll.documentView = feedDoc
        feed.contentView!.addSubview(scroll)
        feed.orderFrontRegardless()
        _ = NSEvent.addGlobalMonitorForEvents(matching: [.mouseMoved, .scrollWheel]) { [weak self] _ in self?.updateClickThrough() }
        _ = NSEvent.addLocalMonitorForEvents(matching: [.mouseMoved, .scrollWheel]) { [weak self] e in self?.updateClickThrough(); return e }

        input = Panel(NSRect(x: 0, y: 0, width: 380, height: 28))
        input.delegate = self
        field.isBezeled = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.font = .systemFont(ofSize: 13)
        field.cell?.wraps = true  // long messages wrap and the bar grows (fitInput); Shift+Enter starts a new line
        field.cell?.isScrollable = false
        field.lineBreakMode = .byWordWrapping
        field.delegate = self
        grip.image = NSImage(systemSymbolName: "line.3.horizontal", accessibilityDescription: "Drag to move")
        grip.contentTintColor = .tertiaryLabelColor
        grip.setContentHuggingPriority(.required, for: .horizontal)
        let row = NSStackView(views: [grip, field])
        row.spacing = 6
        field.topAnchor.constraint(equalTo: row.topAnchor).isActive = true  // the field fills the bar as it grows
        field.bottomAnchor.constraint(equalTo: row.bottomAnchor).isActive = true
        field.setContentHuggingPriority(.defaultLow, for: .vertical)  // or it would shrink the bar to one line
        let p = pill(row)
        p.menu = ctx
        p.frame = input.contentView!.bounds
        p.autoresizingMask = [.width, .height]
        input.contentView!.addSubview(p)

        hints = Panel(NSRect(x: 0, y: 0, width: 380, height: 20))
        hints.canKey = false
        hints.ignoresMouseEvents = true
        hintLabel.preferredMaxLayoutWidth = 360
        let hp = pill(hintLabel)
        hp.frame = hints.contentView!.bounds
        hp.autoresizingMask = [.width, .height]
        hints.contentView!.addSubview(hp)

        applyLock()
        layout()
        setRoom("public")
    }

    func registerHotKey() {
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, _, _ in
            DispatchQueue.main.async { (NSApp.delegate as? App)?.toggleInput() }
            return noErr
        }, 1, &spec, nil, nil)
        if !bindHotKey(d.integer(forKey: "hotKeyCode"), d.integer(forKey: "hotKeyMods")) {
            show("\(shortcut) is taken by another app; pick another in Settings", dim: true)
        }
    }

    /// Swaps the global shortcut. false if another app already holds that key.
    func bindHotKey(_ code: Int, _ mods: Int) -> Bool {
        if let hotKey { UnregisterEventHotKey(hotKey) }
        hotKey = nil
        return RegisterEventHotKey(UInt32(code), UInt32(mods), EventHotKeyID(signature: 0x50535354, id: 1),
                                   GetApplicationEventTarget(), 0, &hotKey) == noErr
    }

    // MARK: Position (drag any bubble; everything moves together)

    var anchor: NSPoint {  // bottom-left of the input bar; hints and feed sit above it
        get { NSPoint(x: d.double(forKey: "x"), y: d.double(forKey: "y")) }
        set { d.set(newValue.x, forKey: "x"); d.set(newValue.y, forKey: "y") }
    }

    func layout() {
        input.setFrameOrigin(anchor)
        hints.setFrameOrigin(NSPoint(x: anchor.x, y: anchor.y + input.frame.height + 4))
        feed.setFrameOrigin(NSPoint(x: anchor.x, y: anchor.y + input.frame.height + 8))
    }

    /// The chat bar grows with what's typed (up to ~8 lines), so a long message shows whole instead of scrolling sideways.
    func fitInput() {
        let t = field.stringValue, cell = field.cell!.copy() as! NSCell
        cell.stringValue = t.isEmpty || t.hasSuffix("\n") ? t + " " : t  // a new line just started counts
        let h = cell.cellSize(forBounds: NSRect(x: 0, y: 0, width: field.bounds.width, height: 10000)).height
        let height = min(max(28, ceil(h) + 10), 150)
        guard abs(input.frame.height - height) > 0.5 else { return }
        input.setFrame(NSRect(origin: anchor, size: NSSize(width: barWidth, height: height)), display: true)
        layout()
    }

    func windowDidMove(_ n: Notification) {
        guard let w = n.object as? NSWindow, w === feed || w === input else { return }
        let a = w === feed ? NSPoint(x: w.frame.minX, y: w.frame.minY - input.frame.height - 8) : w.frame.origin
        guard a != anchor else { return }
        anchor = a
        layout()
    }

    func applyLock() {
        let locked = d.bool(forKey: "locked")
        updateClickThrough()  // locked = messages are click-through
        grip.isHidden = locked
    }

    @objc func toggleLock() {
        d.set(!d.bool(forKey: "locked"), forKey: "locked")
        applyLock()
    }

    @objc func resetPosition() {
        d.removeObject(forKey: "x")
        d.removeObject(forKey: "y")
        layout()
    }

    // MARK: Feed

    func show(_ text: String, dim: Bool = false) { show(styled(text, dim: dim)) }

    /// A note from Psst or the host: a plain bubble on the left.
    func show(_ text: NSAttributedString) { addRow(bubble(text), right: false, ts: Date().timeIntervalSince1970) }

    /// A chat message: the name (and picture, if they set one) above the bubble; mine tinted. Each side is a setting.
    func showMessage(_ m: Msg, text: NSAttributedString) {
        let from = m.from ?? "?", mine = from == me, r = m.room ?? "public"
        let right = d.string(forKey: mine ? "alignMine" : "alignOthers") == "right"
        let col = NSStackView()
        col.orientation = .vertical
        col.alignment = right ? .trailing : .leading
        col.spacing = 2
        let head = NSMutableAttributedString()
        if !mine { head.append(NSAttributedString(string: m.nick ?? from, attributes: [.font: NSFont.systemFont(ofSize: 11, weight: .semibold), .foregroundColor: nameColor(from, m.color)])) }
        if r != "public" { head.append(NSAttributedString(string: (mine ? "" : " · ") + "#" + r, attributes: [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.secondaryLabelColor])) }
        if head.length > 0 { col.addArrangedSubview(NSTextField(labelWithAttributedString: head)) }
        col.addArrangedSubview(bubble(text, tint: mine))
        var views: [NSView] = [col]
        if !mine, let img = pics[from].flatMap({ avatarImage($0, name: from, color: nameColor(from, m.color)) }) {
            let v = NSImageView(image: img)
            v.widthAnchor.constraint(equalToConstant: 22).isActive = true
            v.heightAnchor.constraint(equalToConstant: 22).isActive = true
            views.insert(v, at: right ? 1 : 0)  // on the outer side
        }
        let line = NSStackView(views: views)
        line.alignment = .bottom
        line.spacing = 6
        addRow(line, right: right, ts: m.ts ?? Date().timeIntervalSince1970)
    }

    func bubble(_ text: NSAttributedString, tint: Bool = false) -> Bubble {
        let label = NSTextField(wrappingLabelWithString: "")
        label.attributedStringValue = text
        label.isSelectable = false
        label.preferredMaxLayoutWidth = 300
        let b = pill(label)
        b.menu = ctx
        if tint {  // mine: the accent color through the blur
            let t = NSView(frame: b.bounds)
            t.autoresizingMask = [.width, .height]
            t.wantsLayer = true
            t.layer?.backgroundColor = NSColor.controlAccentColor.withAlphaComponent(0.45).cgColor
            b.addSubview(t, positioned: .below, relativeTo: nil)
        }
        return b
    }

    /// Adds a feed row in time order, so history replayed from the host slots in above newer rows.
    /// `keep`: it stays until removed, instead of fading.
    @discardableResult func addRow(_ content: NSView, right: Bool, ts: Double, keep: Bool = false) -> Row {
        let row = Row()
        row.ts = ts
        content.translatesAutoresizingMaskIntoConstraints = false
        row.addSubview(content)
        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: row.topAnchor),
            content.bottomAnchor.constraint(equalTo: row.bottomAnchor),
            right ? content.trailingAnchor.constraint(equalTo: row.trailingAnchor) : content.leadingAnchor.constraint(equalTo: row.leadingAnchor),
            right ? content.leadingAnchor.constraint(greaterThanOrEqualTo: row.leadingAnchor)
                 : content.trailingAnchor.constraint(lessThanOrEqualTo: row.trailingAnchor),
        ])
        let rows = stack.arrangedSubviews
        stack.insertArrangedSubview(row, at: rows.firstIndex { (($0 as? Row)?.ts ?? 0) > ts } ?? rows.count)
        row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        while stack.arrangedSubviews.count > (history ? 300 : 8) { drop(stack.arrangedSubviews[0]) }
        fitFeed()
        if !history, !keep { fade(row) }
        return row
    }

    func fade(_ row: NSView) {
        DispatchQueue.main.asyncAfter(deadline: .now() + d.double(forKey: "cooldown")) { [weak self, weak row] in
            guard let self, let row, !self.history else { return }  // history turned on meanwhile: it stays
            NSAnimationContext.runAnimationGroup({ $0.duration = 0.5; row.animator().alphaValue = 0 }) { [weak self] in self?.drop(row) }
        }
    }

    /// /history on: every message stays and the feed scrolls back. Off: back to fading, newest few first.
    func setHistory(_ on: Bool) {
        d.set(on, forKey: "history")
        if !on {
            stack.arrangedSubviews.dropLast(8).forEach(drop)
            stack.arrangedSubviews.forEach(fade)
        }
        fitFeed()
        show(on ? "history on: messages stay; scroll up for older ones" : "history off: messages fade again", dim: true)
    }

    func drop(_ v: NSView) {
        stack.removeArrangedSubview(v)
        v.removeFromSuperview()
        fitFeed()
    }

    /// The feed grows upward with its rows up to a cap, then scrolls. It stays at the newest unless you scrolled up.
    func fitFeed() {
        let h = stack.fittingSize.height, shown = max(min(h, history ? 320 : 480), 1)
        let atEnd = feedDoc.visibleRect.maxY >= feedDoc.frame.height - 4
        feedDoc.frame = NSRect(x: 0, y: 0, width: barWidth, height: h)
        feed.setFrame(NSRect(x: feed.frame.minX, y: feed.frame.minY, width: barWidth, height: shown), display: true)
        if atEnd || !history { feedDoc.scroll(NSPoint(x: 0, y: max(h - shown, 0))) }
        updateClickThrough()
    }

    /// The feed is a full-width column, but only its bubbles take the mouse (to drag, or right-click); the rest is
    /// click-through to whatever is behind. With history on it takes the mouse anywhere over it, to scroll.
    func updateClickThrough() {
        let p = NSEvent.mouseLocation
        var over = feed.frame.contains(p) && (history || !d.bool(forKey: "locked"))
        if over, !history {
            var v = feed.contentView?.hitTest(feed.convertPoint(fromScreen: p))
            while let x = v, !(x is Bubble) { v = x.superview }
            over = v != nil
        }
        if feed.ignoresMouseEvents == over { feed.ignoresMouseEvents = !over }
    }

}

extension App {
    // MARK: Menus

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        func add(_ title: String, _ action: Selector? = nil, _ obj: Any? = nil, on: Bool = false, indent: Bool = false) {
            let i = NSMenuItem(title: title, action: action, keyEquivalent: "")
            i.target = self
            i.representedObject = obj
            i.state = on ? .on : .off
            i.indentationLevel = indent ? 1 : 0
            menu.addItem(i)
        }
        if menu === ctx {
            add("Lock position", #selector(toggleLock), on: d.bool(forKey: "locked"))
            add("Reset position", #selector(resetPosition))
            return
        }
        add(me.isEmpty ? "Looking for other machines…" : "\(me) in #\(room) · \(via)")
        add("Write…   \(shortcut)", #selector(toggleInput))
        menu.addItem(.separator())

        add(room == "public" ? "Online (/online for options)" : "Online: click to invite to #\(room)")
        for n in roster where n != me {
            add((friends.contains(n) ? "★ " : "") + n, room == "public" ? nil : #selector(invite(_:)), n, indent: true)
        }
        menu.addItem(.separator())

        add("Settings…", #selector(openSettings))
        if updateText(latest, state: nil).canUpdate { add("Update available: \(latest!)…", #selector(updateNow)) }
        else { add("Psst \(appVersion)" + (d.bool(forKey: "autoUpdate") ? ", updates itself" : "")) }
        menu.addItem(NSMenuItem(title: "Quit Psst", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }
}
