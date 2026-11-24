// Psst — tiny LAN overlay messenger for macOS. One file, no dependencies.
//
// Build: ./build.sh     Run: open Psst.app     Test: Psst.app/Contents/MacOS/Psst --selftest
//
// One Mac types /host; every other Psst on the network finds it via Bonjour.
// ⌥Space opens the input. Enter sends, Esc closes, ⌘Q or /quit quits.
// Typing / lists commands, :name suggests emoji (↑↓ pick, Tab/Enter accept). Messages support inline **markdown**.
// Drag any bubble to move the overlay; right-click to lock it in place.
// First launch asks for a username (changeable once every 2 weeks). /settings opens visibility and other options.
// /friend list|add|remove and /block are kept on this Mac only.
// Messages fade after the cooldown each user picks. The host keeps history in memory only
// and erases it after the retention period it picks. Nothing touches disk except settings.

import AppKit
import Network
import Carbon.HIToolbox
import CryptoKit

let serviceType = "_psst._tcp"
let port: NWEndpoint.Port = 47820
let maxLine = 65536, maxText = 500, maxHistory = 500

// MARK: - Updates: signed GitHub releases

let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
let releases = "https://github.com/sbrothers7/psst/releases/latest/download/"  // not the API: no rate limit for a school sharing one IP
let updateKey = "Oyw6t/z9rkWjGdtYZdOm8b3eekjGoH1HCViAYbINriA="  // Ed25519 public key; the private half never leaves the release Mac (~/.config/psst/update.key)

func isNewer(_ v: String, than current: String) -> Bool {
    v.trimmingCharacters(in: .whitespacesAndNewlines).compare(current, options: .numeric) == .orderedDescending
}

/// Only zips signed by the release key may install, so a hijacked GitHub account can't push code to every Mac.
func verified(_ data: Data, sig: Data, key: String = updateKey) -> Bool {
    guard let k = Data(base64Encoded: key).flatMap({ try? Curve25519.Signing.PublicKey(rawRepresentation: $0) }),
          let s = Data(base64Encoded: String(decoding: sig, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
    else { return false }
    return k.isValidSignature(s, for: data)
}

struct Msg: Codable {
    var t: String
    var room: String? = nil
    var from: String? = nil
    var text: String? = nil
    var names: [String]? = nil
    var ts: Double? = nil
    var hidden: Bool? = nil  // hello/nick: keep me off the online list
}

/// Names and room names: letters, digits, - and _, max 20 chars.
func clean(_ s: String, lower: Bool = false) -> String {
    let ok = s.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
    return String((lower ? ok.lowercased() : ok).prefix(20))
}

func validName(_ n: String) -> Bool { (2...20).contains(n.count) && clean(n) == n }

// ponytail: enforced on this Mac only; a host can't check it without accounts. Fine for a school LAN.
let nameCooldown: TimeInterval = 14 * 86400

/// Seconds until the name may change again (0 = now).
func nameChangeLeft(since: Date?, now: Date = Date()) -> TimeInterval {
    guard let since else { return 0 }
    return max(0, since.addingTimeInterval(nameCooldown).timeIntervalSince(now))
}

// MARK: - :shortcode: → emoji

let emojiAliases: [String: String] = [
    "+1": "👍", "thumbsup": "👍", "-1": "👎", "thumbsdown": "👎", "heart": "❤️", "joy": "😂", "rofl": "🤣",
    "smile": "😄", "laughing": "😆", "sweat_smile": "😅", "wink": "😉", "slight_smile": "🙂", "upside_down": "🙃",
    "heart_eyes": "😍", "sunglasses": "😎", "nerd": "🤓", "thinking": "🤔", "cry": "😢", "sob": "😭", "angry": "😠",
    "rage": "😡", "shrug": "🤷", "facepalm": "🤦", "pray": "🙏", "clap": "👏", "wave": "👋", "ok_hand": "👌",
    "100": "💯", "tada": "🎉", "star": "⭐", "check": "✅", "x": "❌", "poop": "💩", "zzz": "💤",
]
let shortcode = try! NSRegularExpression(pattern: ":([a-z0-9_+-]+):", options: .caseInsensitive)

/// Any Unicode character by name: "fire" → 🔥, "grinning" → 😀 (tries "… FACE"), "greek_small_letter_pi" → π.
func unicodeNamed(_ code: String) -> String? {
    let name = code.replacingOccurrences(of: "_", with: " ").uppercased()
    for n in [name, name + " FACE"] {
        guard let c = "\\N{\(n)}".applyingTransform(.toUnicodeName, reverse: true), c.count == 1,
              let u = c.unicodeScalars.first else { continue }
        return asEmoji(u)
    }
    return nil
}

/// Text-style symbols (❤, ☀) need VS16 to render as color emoji.
func asEmoji(_ u: Unicode.Scalar) -> String {
    u.properties.isEmoji && !u.properties.isEmojiPresentation && !u.isASCII ? String(u) + "\u{FE0F}" : String(u)
}

/// Every single-scalar emoji by Unicode name (~1400), aliases first. Feeds the :emoji typing guide.
let emojiIndex: [(code: String, emoji: String)] = {
    var list = emojiAliases.sorted { $0.key < $1.key }.map { (code: $0.key, emoji: $0.value) }
    for range in [0x2300...0x23FF, 0x2600...0x27BF, 0x2B00...0x2BFF, 0x1F300...0x1FAFF] {
        for v in range {
            guard let u = Unicode.Scalar(v), u.properties.isEmoji, !u.properties.isEmojiModifier,
                  let name = u.properties.name else { continue }
            list.append((code: name.lowercased().replacingOccurrences(of: " ", with: "_"), emoji: asEmoji(u)))
        }
    }
    return list
}()

// MARK: - Typing guide

let commands: [(name: String, arg: String, help: String)] = [
    ("/room", "name", "create a private room"),
    ("/invite", "name", "invite someone to this room"),
    ("/join", "room", "join a room you were invited to, or public"),
    ("/leave", "", "leave this room"),
    ("/who", "", "who's online"),
    ("/friend", "list|add|remove name", "friends; list shows who's online"),
    ("/block", "name", "block or unblock someone; alone lists blocked"),
    ("/nick", "name", "change your name (once every 2 weeks)"),
    ("/history", "", "replay this room's recent messages"),
    ("/settings", "", "name, visibility, invites, fade time"),
    ("/setup", "", "show the welcome and setup again"),
    ("/host", "", "start or stop hosting on this Mac"),
    ("/quit", "", "quit Psst (or ⌘Q)"),
]

func usage(_ c: (name: String, arg: String, help: String)) -> String { c.arg.isEmpty ? c.name : "\(c.name) ‹\(c.arg)›" }

struct Suggestion { var label: String, detail = "", replace: String }  // replace = whole field text after accepting

func suggest(_ text: String, roster: [String], rooms: [String], friends: [String] = [], blocked: [String] = []) -> [Suggestion] {
    if text.hasPrefix("/") {
        let parts = text.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        let typed = parts[0].lowercased()
        guard parts.count == 2 else {  // still typing the command name
            return commands.filter { $0.name.hasPrefix(typed) }
                .map { Suggestion(label: usage($0), detail: $0.help, replace: $0.arg.isEmpty ? $0.name : $0.name + " ") }
        }
        guard let cmd = commands.first(where: { $0.name == typed }) else { return [] }
        let words = parts[1].split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        let token = words.last!.lowercased(), base = String(text.dropLast(words.last!.count))
        var options: [String] = []
        switch (cmd.name, words.count) {
        case ("/invite", 1): options = roster
        case ("/join", 1): options = rooms
        case ("/block", 1): options = roster + blocked.filter { !roster.contains($0) }
        case ("/friend", 1): options = ["list", "add ", "remove "]
        case ("/friend", 2) where words[0] == "add": options = roster.filter { !friends.contains($0) }
        case ("/friend", 2) where words[0] == "remove": options = friends
        default: break
        }
        let hits = options.filter { $0.lowercased().hasPrefix(token) }
            .map { Suggestion(label: String(base.dropFirst(cmd.name.count + 1)) + $0, replace: base + $0) }
        return hits.isEmpty ? [Suggestion(label: usage(cmd), detail: cmd.help, replace: text)] : hits  // else: show the format
    }
    guard let r = text.range(of: #"(?<!\S):[a-z0-9_+-]{2,}$"#, options: [.regularExpression, .caseInsensitive]) else { return [] }
    let q = text[r].dropFirst().lowercased()
    let exact = emojiIndex.filter { $0.code == q }
    let prefix = emojiIndex.filter { $0.code.hasPrefix(q) && $0.code != q }.sorted { $0.code.count < $1.code.count }
    let inside = emojiIndex.filter { $0.code.contains(q) && !$0.code.hasPrefix(q) }.sorted { $0.code.count < $1.code.count }
    var seen = Set<String>()
    return (exact + prefix + inside).filter { seen.insert($0.emoji).inserted }.prefix(6)
        .map { Suggestion(label: "\($0.emoji)  :\($0.code):", replace: String(text[..<r.lowerBound]) + $0.emoji) }
}

// MARK: - Text styling

func styled(_ s: String, dim: Bool = false, bold: Bool = false) -> NSAttributedString {
    NSAttributedString(string: s, attributes: [.font: NSFont.systemFont(ofSize: 12, weight: bold ? .semibold : .regular),
                                               .foregroundColor: dim ? NSColor.secondaryLabelColor : NSColor.labelColor])
}

/// Inline markdown: **bold**, *italic*, `code`, ~~strike~~, [link](url).
/// Foundation parses it; AppKit labels ignore the parsed intents, so they're mapped to fonts here.
func markdown(_ s: String, size: CGFloat = 12) -> NSAttributedString {
    let base = NSFont.systemFont(ofSize: size)
    guard let md = try? AttributedString(markdown: s, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))
    else { return NSAttributedString(string: s, attributes: [.font: base, .foregroundColor: NSColor.labelColor]) }
    let out = NSMutableAttributedString()
    for run in md.runs {
        let intent = run.inlinePresentationIntent ?? []
        var font = intent.contains(.code) ? NSFont.monospacedSystemFont(ofSize: size - 1, weight: .regular) : base
        var traits: NSFontDescriptor.SymbolicTraits = []
        if intent.contains(.stronglyEmphasized) { traits.insert(.bold) }
        if intent.contains(.emphasized) { traits.insert(.italic) }
        if !traits.isEmpty { font = NSFont(descriptor: font.fontDescriptor.withSymbolicTraits(traits), size: font.pointSize) ?? font }
        var attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: run.link == nil ? NSColor.labelColor : NSColor.linkColor]
        if intent.contains(.strikethrough) { attrs[.strikethroughStyle] = NSUnderlineStyle.single.rawValue }
        if intent.contains(.code) { attrs[.backgroundColor] = NSColor.white.withAlphaComponent(0.12) }
        out.append(NSAttributedString(string: String(md[run.range].characters), attributes: attrs))
    }
    return out
}

/// Replaces known :shortcodes:, leaves everything else (like 10:30:45) alone.
func emojify(_ s: String) -> String {
    let out = NSMutableString(string: s)
    for m in shortcode.matches(in: s, range: NSRange(s.startIndex..., in: s)).reversed() {
        let code = out.substring(with: m.range(at: 1)).lowercased()
        if let e = emojiAliases[code] ?? unicodeNamed(code) { out.replaceCharacters(in: m.range, with: e) }
    }
    return out as String
}

// MARK: - Wire: newline-delimited JSON over one TCP connection

final class Line {
    let conn: NWConnection
    var onMsg: (Msg) -> Void = { _ in }
    var onClose: () -> Void = {}
    private var buf = Data(), closed = false

    init(_ conn: NWConnection) { self.conn = conn }

    func start() {
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .waiting, .failed: self?.conn.cancel()
            case .cancelled: self?.finish()
            default: break
            }
        }
        conn.start(queue: .main)
        read()
    }

    func send(_ m: Msg) {
        guard !closed, var data = try? JSONEncoder().encode(m) else { return }
        data.append(10)
        conn.send(content: data, completion: .idempotent)
    }

    func close() { conn.cancel() }

    private func finish() {
        guard !closed else { return }
        closed = true
        onClose()
    }

    private func read() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, error in
            guard let self, !self.closed else { return }
            if let data { self.buf.append(data) }
            while let i = self.buf.firstIndex(of: 10) {
                let line = self.buf[self.buf.startIndex..<i]
                self.buf = Data(self.buf[(i + 1)...])
                if let m = try? JSONDecoder().decode(Msg.self, from: line) { self.onMsg(m) }
            }
            if done || error != nil || self.buf.count > maxLine { self.close() } else { self.read() }
        }
    }
}

// MARK: - Host: routes messages, owns rooms, invites and history (memory only)

final class Server {
    struct Client {
        var name = "anon"
        var hidden = false
        var rooms: Set<String> = ["public"]
        let send: (Msg) -> Void
        let close: () -> Void
    }
    var clients: [Int: Client] = [:]
    var invites: [String: Set<Int>] = [:]  // room -> invited client ids
    var history: [Msg] = []
    var retention: Double
    private var listener: NWListener?, timer: Timer?, nextID = 0

    init(retention: Double) { self.retention = retention }

    /// `advertise`: name shown in other Macs' host list (the host's username, not the machine name). nil = loopback only.
    func start(advertise: String?) {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        guard let l = try? NWListener(using: params, on: port) else { return NSLog("psst: can't listen on \(port)") }
        if let advertise { l.service = NWListener.Service(name: advertise, type: serviceType) }
        l.stateUpdateHandler = { if case .failed(let e) = $0 { NSLog("psst: listener failed: \(e)") } }
        l.newConnectionHandler = { [weak self] conn in
            guard let self else { return conn.cancel() }
            self.nextID += 1
            let id = self.nextID, line = Line(conn)
            line.onMsg = { [weak self] in self?.handle(id, $0) }
            line.onClose = { [weak self] in self?.remove(id) }
            self.add(id, send: line.send, close: line.close)
            line.start()
        }
        l.start(queue: .main)
        listener = l
        timer = .scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.purge() }
    }

    func stop() {
        listener?.cancel()
        timer?.invalidate()
        clients.values.forEach { $0.close() }
        clients = [:]
    }

    func add(_ id: Int, send: @escaping (Msg) -> Void, close: @escaping () -> Void) {
        clients[id] = Client(send: send, close: close)
    }

    func remove(_ id: Int) {
        guard clients.removeValue(forKey: id) != nil else { return }
        roster()
    }

    // ponytail: no rate limit; one client can flood. Add a per-client token bucket here if that happens.
    func handle(_ id: Int, _ m: Msg) {
        guard var c = clients[id] else { return }
        let room = clean(m.room ?? "public", lower: true)
        func note(_ text: String, _ r: String? = nil) { c.send(Msg(t: "note", room: r, text: text)) }

        switch m.t {
        case "hello", "nick":
            c.name = unique(clean(m.from ?? ""), id)
            c.hidden = m.hidden ?? false
            clients[id] = c
            c.send(Msg(t: "you", from: c.name))
            if m.t == "hello" { replay("public", to: c) }
            roster()

        case "say":
            let text = String((m.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines).prefix(maxText))
            guard c.rooms.contains(room), !text.isEmpty else { return }
            let out = Msg(t: "say", room: room, from: c.name, text: text, ts: Date().timeIntervalSince1970)
            history.append(out)
            if history.count > maxHistory { history.removeFirst(history.count - maxHistory) }
            send(out, to: room)

        case "create":
            guard !room.isEmpty, room != "public",
                  !clients.values.contains(where: { $0.rooms.contains(room) }) else { return note("#\(room) is taken") }
            invites[room] = nil                    // stale invites and history of an old room with the same name die here
            history.removeAll { $0.room == room }
            c.rooms.insert(room)
            clients[id] = c
            c.send(Msg(t: "joined", room: room))

        case "join":
            guard room == "public" || c.rooms.contains(room) || invites[room]?.contains(id) == true
            else { return note("#\(room) needs an invite") }
            invites[room]?.remove(id)
            if c.rooms.insert(room).inserted {
                clients[id] = c
                send(Msg(t: "note", room: room, text: "\(c.name) joined"), to: room)
            }
            c.send(Msg(t: "joined", room: room))
            replay(room, to: c)

        case "invite":
            let name = clean(m.text ?? "")
            guard room != "public", c.rooms.contains(room) else { return note("make a room first: /room name") }
            guard let target = clients.first(where: { $0.value.name == name && !$0.value.hidden })
            else { return note("no one named \(name)") }  // invisible people can't be found by name either
            guard !target.value.rooms.contains(room) else { return note("\(name) is already here", room) }
            invites[room, default: []].insert(target.key)
            target.value.send(Msg(t: "invite", room: room, from: c.name))
            note("invited \(name)", room)

        case "leave":
            guard room != "public", c.rooms.remove(room) != nil else { return }
            clients[id] = c
            c.send(Msg(t: "left", room: room))
            send(Msg(t: "note", room: room, text: "\(c.name) left"), to: room)

        case "history":
            if c.rooms.contains(room) { replay(room, to: c) }

        default: break
        }
    }

    func send(_ m: Msg, to room: String) {
        for c in clients.values where c.rooms.contains(room) { c.send(m) }
    }

    func replay(_ room: String, to c: Client) {
        for m in history where m.room == room { c.send(m) }
    }

    func roster() {
        let names = clients.values.filter { !$0.hidden }.map(\.name).sorted()
        for c in clients.values { c.send(Msg(t: "who", names: names)) }
    }

    func purge() {
        let cutoff = Date().timeIntervalSince1970 - retention
        history.removeAll { ($0.ts ?? 0) < cutoff }
    }

    func unique(_ base: String, _ id: Int) -> String {
        let base = base.isEmpty ? "anon" : base
        var name = base, i = 2
        while clients.contains(where: { $0.key != id && $0.value.name == name }) { name = "\(base)\(i)"; i += 1 }
        return name
    }
}

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

// MARK: - Client app

final class App: NSObject, NSApplicationDelegate, NSMenuDelegate, NSTextFieldDelegate, NSWindowDelegate {
    let d = UserDefaults.standard
    var server: Server?
    var line: Line?
    var browser: NWBrowser?
    var hosts: [NWBrowser.Result] = []
    var me = "", room = "public", via = "", roster: [String] = [], rooms: Set<String> = [], invited: Set<String> = []
    let status = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    let stack = NSStackView(), field = NSTextField(), hintLabel = NSTextField(wrappingLabelWithString: "")
    let grip = NSImageView(), ctx = NSMenu()
    var feed: Panel!, input: Panel!, hints: Panel!
    var suggestions: [Suggestion] = [], pick = 0
    var hotKey: EventHotKeyRef?
    var settings: NSWindow?
    let box = NSStackView(), welcomeText = NSTextField(wrappingLabelWithString: "")
    let nameField = NSTextField(), nameNote = NSTextField(wrappingLabelWithString: "")
    let lockBox = NSButton(checkboxWithTitle: "Lock overlay position", target: nil, action: nil)
    let saveButton = NSButton(title: "Save", target: nil, action: nil)
    var popups: [NSPopUpButton] = []

    var name: String? { d.string(forKey: "name") }  // nil until picked on first launch
    var friends: [String] {
        get { d.stringArray(forKey: "friends") ?? [] }
        set { d.set(newValue, forKey: "friends") }
    }
    var blocked: [String] {
        get { d.stringArray(forKey: "blocked") ?? [] }
        set { d.set(newValue, forKey: "blocked") }
    }

    func applicationDidFinishLaunching(_ n: Notification) {
        let f = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 800, height: 600)
        d.register(defaults: ["cooldown": 10.0, "retention": 600.0, "invisible": false, "invites": "everyone",
                              "x": f.minX + 12, "y": f.minY + 12])
        buildUI()
        registerHotKey()
        if name == nil { showSettings(welcome: true) }  // first launch: pick a username before anything connects
        checkForUpdate()
        Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { [weak self] _ in self?.checkForUpdate() }

        let b = NWBrowser(for: .bonjour(type: serviceType, domain: nil), using: .tcp)
        b.browseResultsChangedHandler = { [weak self] results, _ in
            self?.hosts = Array(results)
            self?.connect()
        }
        b.start(queue: .main)
        browser = b
        if d.bool(forKey: "hosting") { setHosting(true) }
    }

    func buildUI() {
        status.button?.image = NSImage(systemSymbolName: "bubble.left", accessibilityDescription: "Psst")
        status.button?.appearsDisabled = true
        let menu = NSMenu()
        menu.delegate = self
        status.menu = menu
        ctx.delegate = self  // right-click menu on the overlay, filled in menuNeedsUpdate

        feed = Panel(.zero)  // sized to its bubbles, so empty space never catches clicks
        feed.canKey = false
        feed.delegate = self
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        stack.translatesAutoresizingMaskIntoConstraints = false
        let fc = feed.contentView!
        fc.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: fc.leadingAnchor),
            stack.bottomAnchor.constraint(equalTo: fc.bottomAnchor),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: fc.trailingAnchor),
        ])
        feed.orderFrontRegardless()

        input = Panel(NSRect(x: 0, y: 0, width: 380, height: 28))
        input.delegate = self
        field.isBezeled = false
        field.drawsBackground = false
        field.focusRingType = .none
        field.font = .systemFont(ofSize: 13)
        field.cell?.usesSingleLineMode = true
        field.delegate = self
        grip.image = NSImage(systemSymbolName: "line.3.horizontal", accessibilityDescription: "Drag to move")
        grip.contentTintColor = .tertiaryLabelColor
        grip.setContentHuggingPriority(.required, for: .horizontal)
        let row = NSStackView(views: [grip, field])
        row.spacing = 6
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
        let err = RegisterEventHotKey(UInt32(kVK_Space), UInt32(optionKey), EventHotKeyID(signature: 0x50535354, id: 1),
                                      GetApplicationEventTarget(), 0, &hotKey)
        if err != noErr { show("⌥Space is taken by another app; use the menu bar icon", dim: true) }
    }

    // MARK: Position (drag any bubble; everything moves together)

    var anchor: NSPoint {  // bottom-left of the input bar; hints and feed sit above it
        get { NSPoint(x: d.double(forKey: "x"), y: d.double(forKey: "y")) }
        set { d.set(newValue.x, forKey: "x"); d.set(newValue.y, forKey: "y") }
    }

    func layout() {
        input.setFrameOrigin(anchor)
        hints.setFrameOrigin(NSPoint(x: anchor.x, y: anchor.y + 32))
        feed.setFrameOrigin(NSPoint(x: anchor.x, y: anchor.y + 36))
    }

    func windowDidMove(_ n: Notification) {
        guard let w = n.object as? NSWindow, w === feed || w === input else { return }
        let a = w === feed ? NSPoint(x: w.frame.minX, y: w.frame.minY - 36) : w.frame.origin
        guard a != anchor else { return }
        anchor = a
        layout()
    }

    func applyLock() {
        let locked = d.bool(forKey: "locked")
        feed.ignoresMouseEvents = locked  // locked = messages are click-through
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

    func show(_ text: NSAttributedString) {
        let label = NSTextField(wrappingLabelWithString: "")
        label.attributedStringValue = text
        label.isSelectable = false
        label.preferredMaxLayoutWidth = 340
        let row = pill(label)
        row.menu = ctx
        stack.addArrangedSubview(row)
        while stack.arrangedSubviews.count > 8 { drop(stack.arrangedSubviews[0]) }
        fitFeed()
        DispatchQueue.main.asyncAfter(deadline: .now() + d.double(forKey: "cooldown")) { [weak self] in
            NSAnimationContext.runAnimationGroup({ $0.duration = 0.5; row.animator().alphaValue = 0 }) { self?.drop(row) }
        }
    }

    func drop(_ v: NSView) {
        stack.removeArrangedSubview(v)
        v.removeFromSuperview()
        fitFeed()
    }

    func fitFeed() {
        let s = stack.fittingSize
        feed.setFrame(NSRect(origin: feed.frame.origin, size: NSSize(width: max(s.width, 1), height: max(s.height, 1))), display: true)
    }

    // MARK: Input + typing guide

    @objc func toggleInput() {
        if name == nil { return showSettings(welcome: true) }
        if input.isVisible { return hideInput() }
        input.orderFrontRegardless()
        input.makeKey()
        input.makeFirstResponder(field)
        updateHints()
    }

    func hideInput() {
        input.orderOut(nil)
        hints.orderOut(nil)
    }

    func windowDidResignKey(_ n: Notification) { if (n.object as? Panel) === input { hideInput() } }

    func controlTextDidChange(_ n: Notification) {
        pick = 0
        updateHints()
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy sel: Selector) -> Bool {
        let open = !suggestions.isEmpty
        switch sel {
        case #selector(NSResponder.moveUp(_:)) where open:
            pick = (pick + suggestions.count - 1) % suggestions.count
            updateHints()
        case #selector(NSResponder.moveDown(_:)) where open:
            pick = (pick + 1) % suggestions.count
            updateHints()
        case #selector(NSResponder.insertTab(_:)) where open:
            accept()
        case #selector(NSResponder.insertNewline(_:)):
            if open, suggestions[pick].replace != field.stringValue { accept(); break }
            submit(field.stringValue)
            field.stringValue = ""
            updateHints()
        case #selector(NSResponder.cancelOperation(_:)):
            if open { suggestions = []; hints.orderOut(nil) } else { hideInput() }
        default:
            return false
        }
        return true
    }

    func accept() {
        field.stringValue = suggestions[pick].replace
        field.currentEditor()?.selectedRange = NSRange(location: (field.stringValue as NSString).length, length: 0)
        pick = 0
        updateHints()
    }

    func updateHints() {
        let known = rooms.union(invited).union(["public"]).sorted()
        suggestions = Array(suggest(field.stringValue, roster: roster.filter { $0 != me }, rooms: known,
                                    friends: friends, blocked: blocked).prefix(9))
        guard input.isVisible, !suggestions.isEmpty else { return hints.orderOut(nil) }
        pick = min(pick, suggestions.count - 1)
        let s = NSMutableAttributedString()
        for (i, g) in suggestions.enumerated() {
            if i > 0 { s.append(styled("\n")) }
            s.append(styled((i == pick ? "▸ " : "   ") + g.label, dim: i != pick, bold: i == pick))
            if !g.detail.isEmpty { s.append(styled("   " + g.detail, dim: true)) }
        }
        hintLabel.attributedStringValue = s
        let h = hintLabel.intrinsicContentSize.height + 10
        hints.setFrame(NSRect(x: input.frame.minX, y: input.frame.maxY + 4, width: 380, height: h), display: true)
        hints.orderFrontRegardless()
    }

    func setRoom(_ r: String) {
        room = r
        field.placeholderString = "#\(r) · / commands · : emoji · **markdown**"
    }

    func submit(_ raw: String) {
        let s = raw.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { return }
        let parts = s.split(separator: " ", maxSplits: 1).map(String.init)
        let arg = parts.count > 1 ? parts[1] : ""
        func note(_ text: String) { show(text, dim: true) }
        switch parts[0] {  // these work without a host
        case "/host":
            setHosting(server == nil)
            return note(server == nil ? "stopped hosting" : "hosting on this Mac as \(name ?? ""); others on the network will find it")
        case "/quit": return NSApp.terminate(nil)
        case "/settings": return showSettings(welcome: false)
        case "/setup": return showSettings(welcome: true)
        case "/nick": return note(setName(arg))
        case "/friend": return note(friend(arg))
        case "/block":
            let who = clean(arg)
            if who.isEmpty { return note(blocked.isEmpty ? "no one blocked" : "blocked: " + blocked.joined(separator: ", ")) }
            if blocked.contains(who) { blocked.removeAll { $0 == who }; return note("unblocked \(who)") }
            blocked.append(who)
            return note("blocked \(who): you won't see their messages or invites")
        default: break
        }
        guard let line, !me.isEmpty else { return note("not connected: no host yet. /host to start one") }
        switch parts[0] {
        case "/room": line.send(Msg(t: "create", room: arg))
        case "/join": line.send(Msg(t: "join", room: arg.isEmpty ? "public" : arg))
        case "/invite": line.send(Msg(t: "invite", room: room, text: arg))
        case "/leave": line.send(Msg(t: "leave", room: room))
        case "/history": line.send(Msg(t: "history", room: room))
        case "/who": show("online: " + roster.joined(separator: ", "), dim: true)
        case _ where s.hasPrefix("/"): show(commands.map(usage).joined(separator: " · "), dim: true)
        default: line.send(Msg(t: "say", room: room, text: emojify(s)))
        }
    }

    // MARK: Connection

    func got(_ m: Msg) {
        let r = m.room ?? "public", tag = r == "public" ? "" : "#\(r) ", from = m.from ?? "?"
        if blocked.contains(from), m.t == "say" || m.t == "invite" { return }
        switch m.t {
        case "you": me = m.from ?? ""; status.button?.appearsDisabled = false
        case "who": roster = m.names ?? []
        case "joined": rooms.insert(r); invited.remove(r); setRoom(r)
        case "left": rooms.remove(r); if r == room { setRoom("public") }
        case "invite":
            let policy = d.string(forKey: "invites")
            guard policy == "everyone" || (policy == "friends" && friends.contains(from)) else { return }
            invited.insert(r)
            show("\(from) invited you to #\(r). /join \(r)")
        case "note": show(tag + (m.text ?? ""), dim: true)
        case "say":
            let s = NSMutableAttributedString(attributedString: styled(tag, dim: true))
            s.append(styled("\(m.from ?? "?"): ", bold: true))
            s.append(markdown(m.text ?? ""))
            show(s)
        default: break
        }
    }

    func hostName(_ r: NWBrowser.Result) -> String {
        if case .service(let name, _, _, _) = r.endpoint { return name }
        return "\(r.endpoint)"
    }

    /// Connects to: this Mac if hosting, else the host picked in the menu, else the first one found.
    func connect() {
        guard line == nil, name != nil else { return }
        let ep: NWEndpoint
        if server != nil {
            ep = .hostPort(host: "127.0.0.1", port: port)
            via = "this Mac"
        } else if let r = hosts.first(where: { hostName($0) == d.string(forKey: "host") }) ?? hosts.first {
            ep = r.endpoint
            via = hostName(r)
        } else { return }

        let l = Line(NWConnection(to: ep, using: .tcp))
        line = l
        l.onMsg = { [weak self] in self?.got($0) }
        l.onClose = { [weak self, weak l] in
            guard let self, self.line === l else { return }
            self.line = nil
            self.me = ""
            self.roster = []
            self.rooms = []
            self.invited = []
            self.setRoom("public")
            self.status.button?.appearsDisabled = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.connect() }
        }
        l.start()
        l.send(Msg(t: "hello", from: name, hidden: d.bool(forKey: "invisible")))
    }

    func setHosting(_ on: Bool) {
        server?.stop()
        server = nil
        if on {
            let s = Server(retention: d.double(forKey: "retention"))
            s.start(advertise: name)  // the host list shows the username, not the machine name
            server = s
        }
        d.set(on, forKey: "hosting")
        if let line { line.close() } else { connect() }  // reconnect to the right host
    }

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
        add(me.isEmpty ? "Looking for a host…" : "\(me) in #\(room) via \(via)")
        add("Write…   ⌥Space", #selector(toggleInput))
        menu.addItem(.separator())

        add(room == "public" ? "Online (/room to invite)" : "Online: click to invite to #\(room)")
        for n in roster where n != me {
            add((friends.contains(n) ? "★ " : "") + n, room == "public" ? nil : #selector(invite(_:)), n, indent: true)
        }
        menu.addItem(.separator())

        add(server == nil ? "Hosts on this network" : "Hosting on this Mac (/host to stop)")
        for h in Set(hosts.map(hostName)).sorted() { add(h, #selector(pickHost(_:)), h, on: h == via, indent: true) }
        menu.addItem(.separator())

        add("Settings…", #selector(openSettings))
        add("Psst \(appVersion), updates itself")
        menu.addItem(NSMenuItem(title: "Quit Psst", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    // MARK: Updates

    func checkForUpdate() {
        DispatchQueue.global().async {
            func get(_ file: String) -> Data? { try? Data(contentsOf: URL(string: releases + file)!) }
            guard let v = get("version.txt").map({ String(decoding: $0, as: UTF8.self) }), isNewer(v, than: appVersion),
                  let zip = get("Psst.zip"), let sig = get("Psst.zip.sig") else { return }
            DispatchQueue.main.async { self.install(zip, sig: sig) }
        }
    }

    func install(_ zip: Data, sig: Data) {
        guard verified(zip, sig: sig) else { return show("an update failed its signature check and was skipped", dim: true) }
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("psst-update-\(UUID().uuidString)")
        let new = dir.appendingPathComponent("Psst.app")
        do {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
            try zip.write(to: dir.appendingPathComponent("Psst.zip"))
            let unzip = try Process.run(URL(fileURLWithPath: "/usr/bin/ditto"), arguments: ["-x", "-k", dir.path + "/Psst.zip", dir.path])
            unzip.waitUntilExit()
            let v = Bundle(url: new)?.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
            guard isNewer(v, than: appVersion) else { return }  // never downgrade
            _ = try fm.replaceItemAt(Bundle.main.bundleURL, withItemAt: new)
            show("updated to \(v), restarting…", dim: true)
        } catch {
            return show("update couldn't install: \(error.localizedDescription)", dim: true)
        }
        _ = try? Process.run(URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "sleep 1; /usr/bin/open \"$0\"", Bundle.main.bundlePath])
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { NSApp.terminate(nil) }
    }

    // MARK: Settings, username, friends

    @objc func openSettings() { showSettings(welcome: false) }

    /// welcome = onboarding: first launch and /setup show the how-to on top of the settings.
    func showSettings(welcome: Bool) {
        if settings == nil { settings = buildSettings() }
        let w = settings!
        welcomeText.isHidden = !welcome
        box.setFrameSize(box.fittingSize)
        w.setContentSize(NSSize(width: box.frame.width + 40, height: box.frame.height + 40))
        w.title = welcome ? "Welcome to Psst" : "Psst Settings"
        refreshSettings()
        NSApp.activate(ignoringOtherApps: true)
        w.makeKeyAndOrderFront(nil)
        w.makeFirstResponder(nameField.isEnabled ? nameField : nil)
    }

    func buildSettings() -> NSWindow {
        let w = NSWindow(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        w.delegate = self
        nameField.placeholderString = "2–20 letters, digits, - or _"
        nameField.target = self  // Enter saves
        nameField.action = #selector(saveName)
        nameField.widthAnchor.constraint(equalToConstant: 180).isActive = true
        saveButton.target = self
        saveButton.action = #selector(saveName)
        nameNote.font = .systemFont(ofSize: 11)
        nameNote.textColor = .secondaryLabelColor
        nameNote.preferredMaxLayoutWidth = 260
        lockBox.target = self
        lockBox.action = #selector(lockChanged)
        popups = [
            popup("invisible", [("Show me in the online list", false), ("Invisible: hide me from the online list", true)]),
            popup("invites", [("Everyone", "everyone"), ("Friends only", "friends"), ("Nobody", "nobody")]),
            popup("cooldown", [("5 seconds", 5.0), ("10 seconds", 10.0), ("30 seconds", 30.0), ("1 minute", 60.0)]),
            popup("retention", [("1 minute", 60.0), ("10 minutes", 600.0), ("1 hour", 3600.0), ("1 day", 86400.0)]),
        ]
        func label(_ s: String) -> NSTextField { NSTextField(labelWithString: s) }
        let grid = NSGridView(views: [
            [label("Username"), NSStackView(views: [nameField, saveButton])],
            [NSGridCell.emptyContentView, nameNote],
            [label("Visibility"), popups[0]],
            [label("Room invites from"), popups[1]],
            [label("Messages fade after"), popups[2]],
            [label("When hosting, erase history after"), popups[3]],
            [NSGridCell.emptyContentView, lockBox],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.rowAlignment = .firstBaseline
        grid.rowSpacing = 10
        welcomeText.stringValue = """
            Chat with people on this network. Messages fade away and nothing is saved.
            ⌥Space opens the chat bar. Type / for commands, :name for emoji, **bold** for markdown.
            One person types /host and everyone else connects on their own.
            Drag the bubbles to move them; right-click to lock them in place.
            """
        welcomeText.preferredMaxLayoutWidth = grid.fittingSize.width  // wrap to the settings' width
        box.orientation = .vertical
        box.alignment = .leading
        box.spacing = 18
        box.addArrangedSubview(welcomeText)
        box.addArrangedSubview(grid)
        box.frame.origin = NSPoint(x: 20, y: 20)
        w.contentView!.addSubview(box)
        w.center()
        return w
    }

    func popup(_ key: String, _ opts: [(String, Any)]) -> NSPopUpButton {
        let p = NSPopUpButton()
        p.identifier = NSUserInterfaceItemIdentifier(key)
        p.target = self
        p.action = #selector(popupChanged(_:))
        for (title, v) in opts {
            p.addItem(withTitle: title)
            p.lastItem?.representedObject = v
        }
        return p
    }

    func refreshSettings() {
        let left = nameChangeLeft(since: d.object(forKey: "nameSetAt") as? Date)
        nameField.stringValue = name ?? ""
        nameField.isEnabled = name == nil || left == 0
        saveButton.isEnabled = nameField.isEnabled
        nameNote.stringValue = name == nil ? "Pick the name classmates will see. After this you can change it once every 2 weeks."
            : left > 0 ? "You can change your name again in \(waitText(left))."
            : "You can change your name now, then not again for 2 weeks."
        for p in popups {
            let current = d.object(forKey: p.identifier!.rawValue) as? NSObject
            p.selectItem(at: p.itemArray.firstIndex { ($0.representedObject as? NSObject)?.isEqual(current) == true } ?? 0)
        }
        lockBox.state = d.bool(forKey: "locked") ? .on : .off
    }

    func waitText(_ s: TimeInterval) -> String {
        s > 86400 ? "\(Int((s / 86400).rounded(.up))) days" : "\(Int((s / 3600).rounded(.up))) hours"
    }

    @objc func popupChanged(_ p: NSPopUpButton) {
        let key = p.identifier!.rawValue
        d.set(p.selectedItem?.representedObject, forKey: key)
        if key == "retention" { server?.retention = d.double(forKey: key); server?.purge() }
        if key == "invisible" { line?.send(Msg(t: "nick", from: name, hidden: d.bool(forKey: key))) }
    }

    @objc func lockChanged() {
        d.set(lockBox.state == .on, forKey: "locked")
        applyLock()
    }

    @objc func saveName() {
        let result = setName(nameField.stringValue)
        refreshSettings()
        nameNote.stringValue = result
    }

    func windowWillClose(_ n: Notification) {
        if (n.object as? NSWindow) === settings { NSApp.deactivate() }  // hand focus back to whatever was in front
    }

    /// Sets the username if the 2-week rule allows. Returns what happened, for the user.
    func setName(_ raw: String) -> String {
        let n = raw.trimmingCharacters(in: .whitespaces)
        guard validName(n) else { return "Names are 2–20 letters, digits, - or _." }
        guard n != name else { return "That's already your name." }
        let left = nameChangeLeft(since: d.object(forKey: "nameSetAt") as? Date)
        guard name == nil || left == 0 else { return "You can change your name again in \(waitText(left))." }
        d.set(n, forKey: "name")
        d.set(Date(), forKey: "nameSetAt")
        if let line { line.send(Msg(t: "nick", from: n, hidden: d.bool(forKey: "invisible"))) } else { connect() }
        return "Saved: you're \(n). ⌥Space to chat. Next name change in 2 weeks."
    }

    /// /friend list|add|remove name. Friends are kept on this Mac only.
    func friend(_ arg: String) -> String {
        let w = arg.split(separator: " ").map(String.init)
        let who = w.count > 1 ? clean(w[1]) : ""
        switch (w.first ?? "list", who.isEmpty) {
        case ("list", _):
            let online = friends.filter(roster.contains)
            return friends.isEmpty ? "no friends yet: /friend add name"
                : online.isEmpty ? "no friends online" : "friends online: " + online.joined(separator: ", ")
        case ("add", false):
            guard who != me, who != name else { return "that's you" }
            if !friends.contains(who) { friends.append(who) }
            return "added \(who) to friends" + (roster.contains(who) ? " (online now)" : "")
        case ("remove", false):
            friends.removeAll { $0 == who }
            return "removed \(who) from friends"
        default:
            return "/friend list · /friend add name · /friend remove name"
        }
    }

    @objc func invite(_ i: NSMenuItem) { line?.send(Msg(t: "invite", room: room, text: i.representedObject as? String)) }

    @objc func pickHost(_ i: NSMenuItem) {
        d.set(i.representedObject as? String, forKey: "host")
        if server != nil { setHosting(false) } else { line?.close() }
    }
}

// MARK: - Self-test (host routing + one real TCP round trip)

func check(_ ok: Bool, _ what: String) { if !ok { print("FAIL:", what); exit(1) } }

func selftest() {
    let s = Server(retention: 60)
    var inbox: [Int: [Msg]] = [:]
    for id in 1...3 { s.add(id, send: { inbox[id, default: []].append($0) }, close: {}) }
    func last(_ id: Int) -> Msg? { inbox[id]?.last }
    func saw(_ id: Int, _ text: String) -> Bool { inbox[id]?.contains { $0.text == text } ?? false }

    s.handle(1, Msg(t: "hello", from: "ana"))
    s.handle(2, Msg(t: "hello", from: "ana"))
    s.handle(3, Msg(t: "hello", from: "bo b!"))
    check(s.clients[2]?.name == "ana2", "duplicate names get a suffix")
    check(s.clients[3]?.name == "bob", "names are cleaned")

    s.handle(1, Msg(t: "say", room: "public", text: "hi"))
    check(last(2)?.text == "hi" && last(3)?.from == "ana", "public reaches everyone")
    s.handle(3, Msg(t: "say", room: "public", from: "ana", text: "spoof"))
    check(last(1)?.from == "bob", "sender name comes from host, not client")

    s.add(4, send: { inbox[4, default: []].append($0) }, close: {})
    s.handle(4, Msg(t: "hello", from: "ghost", hidden: true))
    check(last(1)?.t == "who" && last(1)?.names?.contains("ghost") == false, "invisible users stay off the online list")

    s.handle(1, Msg(t: "create", room: "Math"))
    check(last(1)?.t == "joined" && last(1)?.room == "math", "create joins creator")
    s.handle(2, Msg(t: "create", room: "math"))
    check(s.clients[2]?.rooms.contains("math") == false, "can't take an existing room")
    s.handle(2, Msg(t: "join", room: "math"))
    check(s.clients[2]?.rooms.contains("math") == false, "join needs invite")
    s.handle(1, Msg(t: "invite", room: "math", text: "ana2"))
    check(last(2)?.t == "invite", "invite delivered")
    s.handle(2, Msg(t: "join", room: "math"))
    check(s.clients[2]?.rooms.contains("math") == true, "invited user can join")
    s.handle(1, Msg(t: "invite", room: "math", text: "ghost"))
    check(last(1)?.text == "no one named ghost" && last(4)?.t != "invite", "invisible users can't be found to invite")

    s.handle(1, Msg(t: "say", room: "math", text: "secret"))
    check(saw(2, "secret") && !saw(3, "secret"), "room messages stay in room")
    s.handle(3, Msg(t: "say", room: "math", text: "intruder"))
    check(!saw(1, "intruder"), "non-members can't post to room")

    let e = emojify(":fire: :+1: :Grinning: :heart: :greek_small_letter_pi: 10:30:45 :nope: a:b")
    check(e == "🔥 👍 😀 ❤️ π 10:30:45 :nope: a:b", "emojify: \(e)")

    func hint(_ t: String, _ roster: [String] = [], _ rooms: [String] = []) -> [Suggestion] { suggest(t, roster: roster, rooms: rooms) }
    check(hint("/").count == commands.count, "/ lists every command")
    check(hint("/inv").first?.replace == "/invite ", "command completes with room for its argument")
    check(hint("/invite a", ["ana", "bob"]).map(\.replace) == ["/invite ana"], "/invite suggests people")
    check(hint("/join m", [], ["math", "public"]).map(\.replace) == ["/join math"], "/join suggests rooms")
    check(hint("/room ma").first?.label == "/room ‹name›", "free argument shows its format")
    check(hint("/room ma").first?.replace == "/room ma", "format hint doesn't change the text")
    check(hint("hi :fir").first?.replace == "hi 🔥", "emoji suggestions: \(hint("hi :fir").map(\.label))")
    check(hint("at 10:30").isEmpty && hint("a :x").isEmpty, "no emoji guide for times or 1 letter")
    check(hint("/friend ").map(\.replace) == ["/friend list", "/friend add ", "/friend remove "], "/friend shows subcommands")
    check(suggest("/friend add b", roster: ["bo", "bea"], rooms: [], friends: ["bo"]).map(\.replace) == ["/friend add bea"],
          "/friend add suggests people not yet friends")
    check(suggest("/friend remove ", roster: [], rooms: [], friends: ["bo"]).map(\.replace) == ["/friend remove bo"],
          "/friend remove suggests friends")
    check(suggest("/block z", roster: ["ana"], rooms: [], blocked: ["zed"]).map(\.replace) == ["/block zed"], "/block suggests blocked to unblock")

    check(validName("ana_b") && !validName("a") && !validName("bad name") && !validName(String(repeating: "a", count: 21)), "name rules")
    let now = Date()
    check(nameChangeLeft(since: nil, now: now) == 0, "first name is free")
    check(nameChangeLeft(since: now.addingTimeInterval(-86400), now: now) > 12 * 86400, "rename blocked for 2 weeks")
    check(nameChangeLeft(since: now.addingTimeInterval(-15 * 86400), now: now) == 0, "rename allowed after 2 weeks")

    let md = markdown("**b** *i* `c` ~~s~~ plain")
    func font(_ i: Int) -> NSFont? { md.attribute(.font, at: i, effectiveRange: nil) as? NSFont }
    check(md.string == "b i c s plain", "markdown drops markers: \(md.string)")
    check(font(0)?.fontDescriptor.symbolicTraits.contains(.bold) == true, "markdown bold")
    check(font(2)?.fontDescriptor.symbolicTraits.contains(.italic) == true, "markdown italic")
    check(font(4)?.isFixedPitch == true, "markdown code")
    check(md.attribute(.strikethroughStyle, at: 6, effectiveRange: nil) != nil, "markdown strikethrough")
    check(font(8)?.fontDescriptor.symbolicTraits.contains(.bold) == false, "plain text stays plain")

    s.history[0].ts! -= 120
    s.purge()
    check(!s.history.contains { $0.text == "hi" } && s.history.contains { $0.text == "secret" }, "host erases old history")

    // Real listener + framing over loopback.
    let net = Server(retention: 60)
    net.start(advertise: nil)
    RunLoop.main.run(until: Date() + 0.3)
    var got: [Msg] = []
    let a = Line(NWConnection(to: .hostPort(host: "127.0.0.1", port: port), using: .tcp))
    a.onMsg = { got.append($0) }
    a.start()
    a.send(Msg(t: "hello", from: "net"))
    let ping = "ping 👍🏽 한국어 é 👨‍👩‍👧"
    a.send(Msg(t: "say", text: ping))
    let deadline = Date() + 3
    while !got.contains(where: { $0.text == ping }), Date() < deadline { RunLoop.main.run(until: Date() + 0.05) }
    check(got.first?.from == "net", "tcp hello")
    check(got.contains { $0.text == ping }, "tcp say keeps unicode intact")
    net.stop()
    let key = Curve25519.Signing.PrivateKey(), blob = Data("zip bytes".utf8)
    let sig = Data(try! key.signature(for: blob).base64EncodedString().utf8)
    let pub = key.publicKey.rawRepresentation.base64EncodedString()
    check(verified(blob, sig: sig, key: pub), "signed update verifies")
    check(!verified(Data("tampered".utf8), sig: sig, key: pub), "tampered update rejected")
    check(!verified(blob, sig: sig, key: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()),
          "update signed by another key rejected")
    check(isNewer("1.10", than: "1.9") && isNewer("1.0\n", than: "0") && !isNewer("1.2", than: "1.2") && !isNewer("1.1", than: "1.2"),
          "version compare")
    print("selftest ok")
}

// MARK: - Main

let args = CommandLine.arguments
if args.contains("--selftest") { selftest(); exit(0) }

// Release tooling (used by release.sh): --keygen <file> creates the update key, --sign <zip> <keyfile> prints a signature.
if args.count == 3, args[1] == "--keygen" {
    guard !FileManager.default.fileExists(atPath: args[2]) else { print("key already exists; not overwriting"); exit(1) }
    let k = Curve25519.Signing.PrivateKey()
    FileManager.default.createFile(atPath: args[2], contents: Data(k.rawRepresentation.base64EncodedString().utf8),
                                   attributes: [.posixPermissions: 0o600])
    print(k.publicKey.rawRepresentation.base64EncodedString())
    exit(0)
}
if args.count == 4, args[1] == "--sign" {
    guard let zip = FileManager.default.contents(atPath: args[2]), let text = FileManager.default.contents(atPath: args[3]),
          let raw = Data(base64Encoded: String(decoding: text, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)),
          let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw), let sig = try? k.signature(for: zip)
    else { print("can't sign"); exit(1) }
    print(sig.base64EncodedString())
    exit(0)
}

let ns = NSApplication.shared  // must exist before App() touches the status bar
let app = App()
ns.delegate = app
ns.setActivationPolicy(.accessory)
ns.run()
