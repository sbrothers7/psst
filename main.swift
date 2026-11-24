// Psst — tiny LAN overlay messenger for macOS. One file, no dependencies.
//
// Build: ./build.sh     Run: open Psst.app     Test: Psst.app/Contents/MacOS/Psst --selftest

import AppKit
import Network
import Carbon.HIToolbox
import CryptoKit

let serviceType = "_psst._tcp"
let port: NWEndpoint.Port = 47820
let maxLine = 65536, maxText = 500, maxHistory = 500

/// TCP that also runs over peer-to-peer Wi-Fi (AWDL, what AirDrop uses): Macs within ~30 m reach each other
/// directly, even on networks that block devices from talking or have no shared network at all. Wi-Fi must be on.
func tcp() -> NWParameters {
    let p = NWParameters.tcp
    p.includePeerToPeer = true
    return p
}

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
    var hidden: Bool? = nil           // hello/nick: keep me off the online list
    var key: String? = nil            // hello/nick: my public key
    var keys: [String: String]? = nil // who/members: name -> public key
    var ct: String? = nil             // private-room say: the encrypted message
    var wraps: [String: String]? = nil // private-room say: name -> message key locked for that member
    var color: String? = nil          // say: the sender's name color, one of nameColors
}

// MARK: - End-to-end encryption (private rooms)
//
// Each Mac has a long-lived X25519 key. A private-room message is sealed once with a fresh key K (ChaCha20-Poly1305);
// K is then sealed for each member with the key derived from sender × member. The member copy authenticates the room,
// the sender's name and a hash of the ciphertext, so a host that edits, moves or relabels a message makes it fail to open.
// ponytail: static keys, so no forward secrecy; a stolen identity file opens old captured messages. Fine for class chat.

typealias Identity = Curve25519.KeyAgreement.PrivateKey

func publicKey(_ me: Identity) -> String { me.publicKey.rawRepresentation.base64EncodedString() }

func validKey(_ k: String?) -> String? {
    guard let k, let d = Data(base64Encoded: k), d.count == 32 else { return nil }
    return k
}

/// Short code two people compare in person to be sure no one is in the middle.
func fingerprint(_ key: String) -> String {
    let hex = SHA256.hash(data: Data(key.utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
    return stride(from: 0, to: hex.count, by: 4).map { i in
        String(hex[hex.index(hex.startIndex, offsetBy: i)..<hex.index(hex.startIndex, offsetBy: i + 4)])
    }.joined(separator: " ")
}

/// Same key on both ends: me × them == them × me.
func pairKey(_ me: Identity, _ them: String) -> SymmetricKey? {
    guard let d = Data(base64Encoded: them), let pub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: d),
          let secret = try? me.sharedSecretFromKeyAgreement(with: pub) else { return nil }
    return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data("psst-e2ee-v1".utf8), sharedInfo: Data(), outputByteCount: 32)
}

func binding(_ room: String, _ from: String, _ ct: Data) -> Data {
    Data("\(room)\n\(from)\n".utf8) + Data(SHA256.hash(data: ct))
}

/// Encrypts `text` so only `members` (name -> public key) can read it.
func seal(_ text: String, room: String, from: String, to members: [String: String], with me: Identity) -> (ct: String, wraps: [String: String])? {
    let k = SymmetricKey(size: .bits256)
    guard let ct = try? ChaChaPoly.seal(Data(text.utf8), using: k).combined else { return nil }
    let raw = k.withUnsafeBytes { Data($0) }, aad = binding(room, from, ct)
    var wraps: [String: String] = [:]
    for (name, key) in members {
        if let pk = pairKey(me, key), let w = try? ChaChaPoly.seal(raw, using: pk, authenticating: aad).combined {
            wraps[name] = w.base64EncodedString()
        }
    }
    return (ct.base64EncodedString(), wraps)
}

/// Opens a message sealed by `senderKey`'s owner; nil if it wasn't for me or anything was changed on the way.
func open(ct: String, wrap: String, room: String, from: String, senderKey: String, with me: Identity) -> String? {
    guard let c = Data(base64Encoded: ct), let w = Data(base64Encoded: wrap), let pk = pairKey(me, senderKey),
          let raw = try? ChaChaPoly.open(ChaChaPoly.SealedBox(combined: w), using: pk, authenticating: binding(room, from, c)),
          let text = try? ChaChaPoly.open(ChaChaPoly.SealedBox(combined: c), using: SymmetricKey(data: raw))
    else { return nil }
    return String(data: text, encoding: .utf8)
}

/// Trust on first use: the first key seen for a name is remembered. Returns false if `key` differs from it.
func pinned(_ pins: inout [String: String], _ name: String, _ key: String) -> Bool {
    if let old = pins[name] { return old == key }
    pins[name] = key
    return true
}

/// This Mac's identity, in a file only this user can read. Created on first launch.
// ponytail: not the Keychain; ad-hoc signing changes with every update, so Keychain would ask for a password each time.
func loadIdentity() -> Identity {
    let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Psst")
    let file = dir.appendingPathComponent("identity.key")
    if let d = try? Data(contentsOf: file), let k = try? Identity(rawRepresentation: d) { return k }
    let k = Identity()
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: file.path, contents: k.rawRepresentation, attributes: [.posixPermissions: 0o600])
    return k
}

/// Names and room names: letters, digits, - and _, max 20 chars.
func clean(_ s: String, lower: Bool = false) -> String {
    let ok = s.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
    return String((lower ? ok.lowercased() : ok).prefix(20))
}

func validName(_ n: String) -> Bool { (2...20).contains(n.count) && clean(n) == n }

// ponytail: enforced on this Mac only; a host can't check it without accounts.
let nameCooldown: TimeInterval = 14 * 86400

/// Seconds until the name may change again (0 = now).
func nameChangeLeft(since: Date?, now: Date = Date()) -> TimeInterval {
    guard let since else { return 0 }
    return max(0, since.addingTimeInterval(nameCooldown).timeIntervalSince(now))
}

/// /status text: friends first (★), `per` names a page. `page` is 1-based and clamped.
func statusPage(_ names: [String], friends: [String], page: Int, per: Int = 10) -> String {
    let all = names.filter(friends.contains) + names.filter { !friends.contains($0) }
    guard !all.isEmpty else { return "no one online" }
    let pages = (all.count + per - 1) / per, p = min(max(page, 1), pages)
    let shown = all[(p - 1) * per..<min(p * per, all.count)].map { (friends.contains($0) ? "★ " : "") + $0 }
    return "online \(all.count)" + (pages > 1 ? ", page \(p)/\(pages)" : "") + ": " + shown.joined(separator: ", ")
        + (p < pages ? ". /status \(p + 1) for more" : "")
}

// MARK: - Name colors

let nameColors: [(name: String, color: NSColor)] = [
    ("red", .systemRed), ("orange", .systemOrange), ("yellow", .systemYellow), ("green", .systemGreen), ("mint", .systemMint),
    ("teal", .systemTeal), ("blue", .systemBlue), ("indigo", .systemIndigo), ("purple", .systemPurple), ("pink", .systemPink),
]

/// The color someone picked, else one picked from their name (the same on every Mac).
func nameColor(_ name: String, _ pick: String?) -> NSColor {
    if let c = nameColors.first(where: { $0.name == pick }) { return c.color }
    let h = name.unicodeScalars.reduce(UInt32(0)) { $0 &* 31 &+ $1.value }
    return nameColors[Int(h % UInt32(nameColors.count))].color
}

// MARK: - Chat shortcut

/// Carbon modifier mask and label ("⌃⌥Space") for a key press. nil without ⌃ or ⌥: plain or ⌘ keys are other apps' shortcuts.
func hotKeySpec(_ f: NSEvent.ModifierFlags, key: Int, chars: String) -> (mods: Int, label: String)? {
    guard f.contains(.control) || f.contains(.option) else { return nil }
    let on = [(NSEvent.ModifierFlags.control, controlKey, "⌃"), (.option, optionKey, "⌥"), (.shift, shiftKey, "⇧"), (.command, cmdKey, "⌘")]
        .filter { f.contains($0.0) }
    let names = [kVK_Space: "Space", kVK_Return: "↩", kVK_Tab: "⇥", kVK_Delete: "⌫"]  // ponytail: F-keys show as a blank glyph
    return (on.reduce(0) { $0 | $1.1 }, on.map(\.2).joined() + (names[key] ?? chars.uppercased()))
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
    ("/status", "page", "who's online, friends first, 10 per page"),
    ("/friend", "list|add|remove name", "show friend list"),
    ("/block", "name", "block or unblock someone; /block lists blocked"),
    ("/nick", "name", "change your name (once every 2 weeks)"),
    ("/history", "", "replay this room's recent messages"),
    ("/settings", "", "show settings pane"),
    ("/host", "", "start/stop hosting on this machine"),
    ("/key", "name", "show a key code to compare in person; alone shows yours"),
    ("/trust", "name", "accept someone's new key after comparing codes"),
    ("/quit", "", "quit Psst (or ⌘Q)"),
]

/// "/friend ‹list|add|remove› ‹name›": one bracket per parameter.
func usage(_ c: (name: String, arg: String, help: String)) -> String {
    ([c.name] + c.arg.split(separator: " ").map { "‹\($0)›" }).joined(separator: " ")
}

/// Header shown while typing a command's arguments, with the parameter under the cursor as `focus`.
/// "/friend add b" → ("/friend ‹list|add|remove› ‹name›", "‹name›", help). nil for commands without parameters.
func paramGuide(_ text: String) -> (label: String, focus: String, help: String)? {
    let parts = text.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false)
    guard text.hasPrefix("/"), parts.count == 2, let cmd = commands.first(where: { $0.name == parts[0].lowercased() })
    else { return nil }
    let slots = cmd.arg.split(separator: " ").map { "‹\($0)›" }
    guard !slots.isEmpty else { return nil }
    let typing = parts[1].split(separator: " ", omittingEmptySubsequences: false).count - 1
    return (usage(cmd), slots[min(typing, slots.count - 1)], cmd.help)
}

struct Suggestion { var label: String, detail = "", replace: String }  // replace = whole field text after accepting

func suggest(_ text: String, roster: [String], rooms: [String], friends: [String] = [], blocked: [String] = [],
             changed: [String] = []) -> [Suggestion] {
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
        case ("/key", 1): options = roster
        case ("/trust", 1): options = changed
        case ("/friend", 1): options = ["list", "add ", "remove "]
        case ("/friend", 2) where words[0] == "add": options = roster.filter { !friends.contains($0) }
        case ("/friend", 2) where words[0] == "remove": options = friends
        default: break
        }
        let hits = options.filter { $0.lowercased().hasPrefix(token) }
            .map { Suggestion(label: String(base.dropFirst(cmd.name.count + 1)) + $0, replace: base + $0) }
        return hits  // the format itself is the paramGuide header
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

func styled(_ s: String, dim: Bool = false, bold: Bool = false, color: NSColor? = nil) -> NSAttributedString {
    NSAttributedString(string: s, attributes: [.font: NSFont.systemFont(ofSize: 12, weight: bold ? .semibold : .regular),
                                               .foregroundColor: color ?? (dim ? NSColor.secondaryLabelColor : NSColor.labelColor)])
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
        var key = ""  // public key, passed on so members can encrypt to each other
        var rooms: Set<String> = ["public"]
        let send: (Msg) -> Void
        let close: () -> Void
    }
    var clients: [Int: Client] = [:]
    var invites: [String: Set<Int>] = [:]  // room -> invited client ids
    var owners: [String: Int] = [:]        // room -> creator; the room closes when they leave or quit
    var history: [Msg] = []
    var retention: Double
    private var listener: NWListener?, timer: Timer?, nextID = 0

    init(retention: Double) { self.retention = retention }

    /// `advertise`: name shown in other Macs' host list (the host's username, not the machine name). nil = loopback only.
    func start(advertise: String?) {
        let params = tcp()
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

    func remove(_ id: Int) {  // disconnected or quit
        guard let gone = clients.removeValue(forKey: id) else { return }
        for (room, owner) in owners where owner == id { close(room) }
        for room in gone.rooms where owners[room] != nil { members(room) }
        roster()
    }

    /// Deletes a room: everyone in it is sent back to public, its invites and history are erased.
    func close(_ room: String) {
        send(Msg(t: "note", room: room, text: "this room was closed"), to: room)
        for (id, var c) in clients where c.rooms.remove(room) != nil {
            clients[id] = c
            c.send(Msg(t: "left", room: room))
        }
        owners[room] = nil
        invites[room] = nil
        history.removeAll { $0.room == room }
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
            c.key = validKey(m.key) ?? c.key
            clients[id] = c
            c.send(Msg(t: "you", from: c.name))
            if m.t == "hello" { replay("public", to: c) }
            roster()
            for r in c.rooms where r != "public" { members(r) }

        case "say":
            guard c.rooms.contains(room) else { return }
            var out = Msg(t: "say", room: room, from: c.name, ts: Date().timeIntervalSince1970)
            out.color = nameColors.contains { $0.name == m.color } ? m.color : nil
            if room == "public" {
                let text = String((m.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines).prefix(maxText))
                guard !text.isEmpty else { return }
                out.text = text
            } else {  // private rooms carry only ciphertext; plain text is dropped, so the host never holds it
                guard let ct = m.ct, ct.count <= 4096, let wraps = m.wraps, wraps.count <= 256,
                      wraps.values.allSatisfy({ $0.count <= 128 }) else { return }
                out.ct = ct
                out.wraps = wraps
            }
            history.append(out)
            if history.count > maxHistory { history.removeFirst(history.count - maxHistory) }
            send(out, to: room)

        case "create":
            guard !room.isEmpty, room != "public", owners[room] == nil else { return note("#\(room) is taken") }
            owners[room] = id
            c.rooms.insert(room)
            clients[id] = c
            c.send(Msg(t: "joined", room: room))
            members(room)

        case "join":
            guard room == "public" || c.rooms.contains(room) || invites[room]?.contains(id) == true
            else { return note("#\(room) needs an invite") }
            invites[room]?.remove(id)
            if c.rooms.insert(room).inserted {
                clients[id] = c
                send(Msg(t: "note", room: room, text: "\(c.name) joined"), to: room)
                if room != "public" { members(room) }
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
            guard room != "public", c.rooms.contains(room) else { return }
            if owners[room] == id { return close(room) }
            c.rooms.remove(room)
            clients[id] = c
            c.send(Msg(t: "left", room: room))
            send(Msg(t: "note", room: room, text: "\(c.name) left"), to: room)
            members(room)

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
        let shown = clients.values.filter { !$0.hidden }
        let keys = Dictionary(shown.filter { !$0.key.isEmpty }.map { ($0.name, $0.key) }, uniquingKeysWith: { a, _ in a })
        for c in clients.values { c.send(Msg(t: "who", names: shown.map(\.name).sorted(), keys: keys)) }
    }

    /// Tells a private room's members who is in it and their keys, so they can encrypt to each other.
    func members(_ room: String) {
        let inRoom = clients.values.filter { $0.rooms.contains(room) && !$0.key.isEmpty }
        send(Msg(t: "members", room: room, keys: Dictionary(inRoom.map { ($0.name, $0.key) }, uniquingKeysWith: { a, _ in a })), to: room)
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
    var hosts: [NWBrowser.Result] = [], attempts = 0
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
    let shortcutButton = NSButton(title: "", target: nil, action: nil)
    var recorder: Any?  // key monitor while a new shortcut is being typed
    var popups: [NSPopUpButton] = []

    var name: String? { d.string(forKey: "name") }  // nil until picked on first launch
    var shortcut: String { d.string(forKey: "hotKeyLabel") ?? "⌥Space" }
    var friends: [String] {
        get { d.stringArray(forKey: "friends") ?? [] }
        set { d.set(newValue, forKey: "friends") }
    }
    lazy var identity = loadIdentity()
    var known: [String: String] = [:]        // name -> latest public key seen from the host
    var members: [String: [String: String]] = [:]  // private room -> member name -> public key
    var changed: [String: String] = [:]      // name -> new key that doesn't match the remembered one
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
        d.register(defaults: ["cooldown": 10.0, "retention": 600.0, "invisible": false, "invites": "everyone",
                              "color": "auto", "hotKeyCode": kVK_Space, "hotKeyMods": optionKey, "hotKeyLabel": "⌥Space",
                              "x": f.minX + 12, "y": f.minY + 12])
        buildUI()
        registerHotKey()
        if name == nil { showSettings(welcome: true) }  // first launch: pick a username before anything connects
        checkForUpdate()
        Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { [weak self] _ in self?.checkForUpdate() }

        let b = NWBrowser(for: .bonjour(type: serviceType, domain: nil), using: tcp())
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
                                    friends: friends, blocked: blocked, changed: changed.keys.sorted()).prefix(9))
        let guide = paramGuide(field.stringValue)
        guard input.isVisible, !suggestions.isEmpty || guide != nil else { return hints.orderOut(nil) }
        pick = min(pick, max(suggestions.count - 1, 0))
        let s = NSMutableAttributedString()
        if let guide {  // command format, the parameter being typed in accent color
            let line = NSMutableAttributedString(attributedString: styled(guide.label, dim: true))
            if let r = guide.label.range(of: guide.focus) {
                line.addAttributes([.foregroundColor: NSColor.controlAccentColor,
                                    .font: NSFont.systemFont(ofSize: 12, weight: .semibold)], range: NSRange(r, in: guide.label))
            }
            line.append(styled("   " + guide.help, dim: true))
            s.append(line)
        }
        for (i, g) in suggestions.enumerated() {
            if s.length > 0 { s.append(styled("\n")) }
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
        field.placeholderString = "#\(r)\(r == "public" ? "" : " 🔒") · / commands · : emoji · **markdown**"
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
        case "/nick": return note(setName(arg))
        case "/friend": return note(friend(arg))
        case "/block":
            let who = clean(arg)
            if who.isEmpty { return note(blocked.isEmpty ? "no one blocked" : "blocked: " + blocked.joined(separator: ", ")) }
            if blocked.contains(who) { blocked.removeAll { $0 == who }; return note("unblocked \(who)") }
            blocked.append(who)
            return note("blocked \(who): you won't see their messages or invites")
        case "/key":
            let who = clean(arg)
            if who.isEmpty { return note("your key: \(fingerprint(publicKey(identity))). Compare in person with /key \(name ?? "you") on their Mac.") }
            guard let k = known[who] else { return note("no key seen for \(who) yet") }
            return note("\(who): \(fingerprint(k))" + (changed[who] != nil ? ". Changed, not trusted. /trust \(who) once it matches" : ""))
        case "/trust":
            let who = clean(arg)
            guard let k = changed.removeValue(forKey: who) else { return note("nothing to trust for \(who)") }
            pins[who] = k
            return note("trusting \(who)'s new key \(fingerprint(k))")
        default: break
        }
        guard let line, !me.isEmpty else { return note("not connected: no host yet. /host to start one") }
        switch parts[0] {
        case "/room": line.send(Msg(t: "create", room: arg))
        case "/join": line.send(Msg(t: "join", room: arg.isEmpty ? "public" : arg))
        case "/invite": line.send(Msg(t: "invite", room: room, text: arg))
        case "/leave": line.send(Msg(t: "leave", room: room))
        case "/history": line.send(Msg(t: "history", room: room))
        case "/status": show(statusPage(roster, friends: friends, page: Int(arg) ?? 1), dim: true)
        case _ where s.hasPrefix("/"): show(commands.map(usage).joined(separator: " · "), dim: true)
        default:
            let color = d.string(forKey: "color")
            guard room != "public" else { return line.send(Msg(t: "say", room: room, text: emojify(s), color: color)) }
            let to = (members[room] ?? [:]).filter { pins[$0.key] == $0.value }  // only people whose key we trust
            guard let sealed = seal(emojify(s), room: room, from: me, to: to, with: identity)
            else { return note("couldn't encrypt that message") }
            line.send(Msg(t: "say", room: room, ct: sealed.ct, wraps: sealed.wraps, color: color))
        }
    }

    // MARK: Connection

    func got(_ m: Msg) {
        let r = m.room ?? "public", tag = r == "public" ? "" : "#\(r) ", from = m.from ?? "?"
        if blocked.contains(from), m.t == "say" || m.t == "invite" { return }
        switch m.t {
        case "you": me = m.from ?? ""; attempts = 0; status.button?.appearsDisabled = false
        case "who":
            roster = m.names ?? []
            learn(m.keys ?? [:])
        case "members":
            members[r] = m.keys ?? [:]
            learn(m.keys ?? [:])
        case "joined": rooms.insert(r); invited.remove(r); setRoom(r)
        case "left": rooms.remove(r); members[r] = nil; if r == room { setRoom("public") }
        case "invite":
            let policy = d.string(forKey: "invites")
            guard policy == "everyone" || (policy == "friends" && friends.contains(from)) else { return }
            invited.insert(r)
            show("\(from) invited you to #\(r). /join \(r)")
        case "note": show(tag + (m.text ?? ""), dim: true)
        case "say":
            var text = m.text ?? ""
            if r != "public" {  // private: must open with the sender's trusted key, or it isn't shown
                guard let ct = m.ct, let wrap = m.wraps?[me], let key = members[r]?[from] ?? known[from], pins[from] == key,
                      let opened = open(ct: ct, wrap: wrap, room: r, from: from, senderKey: key, with: identity) else { return }
                text = opened
            }
            let s = NSMutableAttributedString(attributedString: styled(tag, dim: true))
            s.append(styled("\(from): ", bold: true, color: nameColor(from, m.color)))
            s.append(markdown(text))
            show(s)
        default: break
        }
    }

    /// Remembers keys; warns once when someone's key differs from the one first seen for that name.
    func learn(_ keys: [String: String]) {
        for (n, k) in keys {
            known[n] = k
            var p = pins
            if pinned(&p, n, k) { pins = p; changed[n] = nil; continue }
            if changed[n] != k {
                changed[n] = k
                show("⚠️ \(n)'s key changed: a new Mac, or someone in the middle. Compare /key \(n) in person, then /trust \(n). Until then they can't read your private-room messages.")
            }
        }
    }

    func hostName(_ r: NWBrowser.Result) -> String {
        if case .service(let name, _, _, _) = r.endpoint { return name }
        return "\(r.endpoint)"
    }

    /// Connects to: this Mac if hosting, else the host picked in the menu, else the first one found.
    /// A host is often reachable over several links (school Wi-Fi, direct peer-to-peer). The first try lets macOS pick;
    /// each retry pins the next link, so a network that silently drops traffic can't trap us on it.
    func connect() {
        guard line == nil, name != nil else { return }
        let ep: NWEndpoint
        var pin: NWInterface? = nil
        if server != nil {
            ep = .hostPort(host: "127.0.0.1", port: port)
            via = "this Mac"
        } else if let r = hosts.first(where: { hostName($0) == d.string(forKey: "host") }) ?? hosts.first {
            let routes: [NWInterface?] = [nil] + r.interfaces.filter { $0.type != .loopback }
            pin = routes[attempts % routes.count]
            attempts += 1
            ep = r.endpoint
            via = hostName(r)
        } else { return }

        let params = tcp()
        params.requiredInterface = pin
        let l = Line(NWConnection(to: ep, using: params))
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self, weak l] in  // no answer in 8 s: next link
            if let self, let l, self.line === l, self.me.isEmpty { l.close() }
        }
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
        l.send(Msg(t: "hello", from: name, hidden: d.bool(forKey: "invisible"), key: publicKey(identity)))
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
        add("Write…   \(shortcut)", #selector(toggleInput))
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

    /// welcome = onboarding: the first launch shows the how-to on top of the settings.
    func showSettings(welcome: Bool) {
        if settings == nil { settings = buildSettings() }
        let w = settings!
        welcomeText.isHidden = !welcome
        welcomeText.stringValue = """
            Chat with people on this network. Messages fade away and nothing is saved.
            \(shortcut) opens the chat bar. Type / for commands, :name for emoji, **bold** for markdown.
            One person types /host and everyone else connects on their own.
            Drag the bubbles to move them; right-click to lock them in place.
            """
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
        shortcutButton.target = self
        shortcutButton.action = #selector(recordShortcut)
        shortcutButton.title = shortcut
        popups = [
            popup("invisible", [("Show me in the online list", false), ("Invisible: hide me from the online list", true)]),
            popup("invites", [("Everyone", "everyone"), ("Friends only", "friends"), ("Nobody", "nobody")]),
            popup("cooldown", [("5 seconds", 5.0), ("10 seconds", 10.0), ("30 seconds", 30.0), ("1 minute", 60.0)]),
            popup("retention", [("1 minute", 60.0), ("10 minutes", 600.0), ("1 hour", 3600.0), ("1 day", 86400.0)]),
            popup("color", [("Auto", "auto")] + nameColors.map { ($0.name.capitalized, $0.name) }),
        ]
        for (item, c) in zip(popups[4].itemArray.dropFirst(), nameColors) { item.image = swatch(c.color) }
        func label(_ s: String) -> NSTextField { NSTextField(labelWithString: s) }
        let grid = NSGridView(views: [
            [label("Username"), NSStackView(views: [nameField, saveButton])],
            [NSGridCell.emptyContentView, nameNote],
            [label("Name color"), popups[4]],
            [label("Chat shortcut"), shortcutButton],
            [label("Visibility"), popups[0]],
            [label("Room invites from"), popups[1]],
            [label("Messages fade after"), popups[2]],
            [label("When hosting, erase history after"), popups[3]],
            [NSGridCell.emptyContentView, lockBox],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.rowAlignment = .firstBaseline
        grid.rowSpacing = 10
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
        popups[4].itemArray.first?.image = swatch(nameColor(name ?? "", nil))  // what Auto gives this name
        shortcutButton.title = shortcut
    }

    func swatch(_ c: NSColor) -> NSImage {
        NSImage(size: NSSize(width: 10, height: 10), flipped: false) { r in c.setFill(); NSBezierPath(ovalIn: r).fill(); return true }
    }

    /// Click, then press the new keys. Esc cancels. The old shortcut is off meanwhile so it can be typed again.
    @objc func recordShortcut() {
        guard recorder == nil else { return }
        if let hotKey { UnregisterEventHotKey(hotKey) }
        hotKey = nil
        shortcutButton.title = "Press keys… (Esc cancels)"
        recorder = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] e in
            guard let self else { return e }
            let code = Int(e.keyCode)
            if code != kVK_Escape {
                guard let spec = hotKeySpec(e.modifierFlags, key: code, chars: e.charactersIgnoringModifiers ?? "") else {
                    self.shortcutButton.title = "Use ⌃ or ⌥ with a key"
                    return nil
                }
                if self.bindHotKey(code, spec.mods) {
                    self.d.set(code, forKey: "hotKeyCode")
                    self.d.set(spec.mods, forKey: "hotKeyMods")
                    self.d.set(spec.label, forKey: "hotKeyLabel")
                } else {
                    self.nameNote.stringValue = "\(spec.label) is taken by another app."
                }
            }
            self.stopRecording()
            return nil
        }
    }

    func stopRecording() {
        guard let r = recorder else { return }
        NSEvent.removeMonitor(r)
        recorder = nil
        if hotKey == nil { _ = bindHotKey(d.integer(forKey: "hotKeyCode"), d.integer(forKey: "hotKeyMods")) }  // cancelled or taken: keep the old one
        shortcutButton.title = shortcut
    }

    func waitText(_ s: TimeInterval) -> String {
        s > 86400 ? "\(Int((s / 86400).rounded(.up))) days" : "\(Int((s / 3600).rounded(.up))) hours"
    }

    @objc func popupChanged(_ p: NSPopUpButton) {
        let key = p.identifier!.rawValue
        d.set(p.selectedItem?.representedObject, forKey: key)
        if key == "retention" { server?.retention = d.double(forKey: key); server?.purge() }
        if key == "invisible" { line?.send(Msg(t: "nick", from: name, hidden: d.bool(forKey: key), key: publicKey(identity))) }
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
        guard (n.object as? NSWindow) === settings else { return }
        stopRecording()
        NSApp.deactivate()  // hand focus back to whatever was in front
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
        if let line { line.send(Msg(t: "nick", from: n, hidden: d.bool(forKey: "invisible"), key: publicKey(identity))) } else { connect() }
        return "Saved: you're \(n). \(shortcut) to chat. Next name change in 2 weeks."
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
    s.handle(1, Msg(t: "say", room: "public", text: "c1", color: "teal"))
    s.handle(1, Msg(t: "say", room: "public", text: "c2", color: "#ff0000; evil"))
    check(last(2)?.text == "c2" && last(2)?.color == nil && inbox[2]!.contains { $0.text == "c1" && $0.color == "teal" },
          "host passes only palette colors")

    s.add(4, send: { inbox[4, default: []].append($0) }, close: {})
    s.handle(4, Msg(t: "hello", from: "ghost", hidden: true))
    check(last(1)?.t == "who" && last(1)?.names?.contains("ghost") == false, "invisible users stay off the online list")

    s.handle(1, Msg(t: "create", room: "Math"))
    check(inbox[1]!.contains { $0.t == "joined" && $0.room == "math" }, "create joins creator")
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

    func sawCT(_ id: Int, _ ct: String) -> Bool { inbox[id]?.contains { $0.ct == ct } ?? false }
    s.handle(1, Msg(t: "say", room: "math", ct: "CT", wraps: ["ana2": "W"]))
    check(sawCT(2, "CT") && !sawCT(3, "CT"), "room messages stay in room")
    s.handle(1, Msg(t: "say", room: "math", text: "plain"))
    check(!saw(2, "plain") && !s.history.contains { $0.text == "plain" }, "host drops plain text in private rooms")
    s.handle(3, Msg(t: "say", room: "math", ct: "X", wraps: [:]))
    check(!sawCT(1, "X"), "non-members can't post to room")

    let e = emojify(":fire: :+1: :Grinning: :heart: :greek_small_letter_pi: 10:30:45 :nope: a:b")
    check(e == "🔥 👍 😀 ❤️ π 10:30:45 :nope: a:b", "emojify: \(e)")

    func hint(_ t: String, _ roster: [String] = [], _ rooms: [String] = []) -> [Suggestion] { suggest(t, roster: roster, rooms: rooms) }
    check(hint("/").count == commands.count, "/ lists every command")
    check(hint("/inv").first?.replace == "/invite ", "command completes with room for its argument")
    check(hint("/invite a", ["ana", "bob"]).map(\.replace) == ["/invite ana"], "/invite suggests people")
    check(hint("/join m", [], ["math", "public"]).map(\.replace) == ["/join math"], "/join suggests rooms")
    check(hint("/room ma").isEmpty, "free argument has nothing to pick")
    check(paramGuide("/room ma")?.label == "/room ‹name›" && paramGuide("/room ma")?.focus == "‹name›", "guide shows format")
    check(paramGuide("/friend a")?.focus == "‹list|add|remove›", "guide highlights first parameter")
    check(paramGuide("/friend add b")?.focus == "‹name›", "guide moves to second parameter")
    check(paramGuide("/friend ")?.label == "/friend ‹list|add|remove› ‹name›", "one bracket per parameter")
    check(paramGuide("/leave ") == nil && paramGuide("/fri") == nil && paramGuide("hi") == nil, "no guide without parameters")
    check(hint("hi :fir").first?.replace == "hi 🔥", "emoji suggestions: \(hint("hi :fir").map(\.label))")
    check(hint("at 10:30").isEmpty && hint("a :x").isEmpty, "no emoji guide for times or 1 letter")
    check(hint("/friend ").map(\.replace) == ["/friend list", "/friend add ", "/friend remove "], "/friend shows subcommands")
    check(suggest("/friend add b", roster: ["bo", "bea"], rooms: [], friends: ["bo"]).map(\.replace) == ["/friend add bea"],
          "/friend add suggests people not yet friends")
    check(suggest("/friend remove ", roster: [], rooms: [], friends: ["bo"]).map(\.replace) == ["/friend remove bo"],
          "/friend remove suggests friends")
    check(suggest("/block z", roster: ["ana"], rooms: [], blocked: ["zed"]).map(\.replace) == ["/block zed"], "/block suggests blocked to unblock")

    let crowd = (1...25).map { "p\($0)" }
    let p1 = statusPage(crowd, friends: ["p20"], page: 1)
    check(p1.hasPrefix("online 25, page 1/3: ★ p20, p1,") && p1.hasSuffix("p9. /status 2 for more"), "status page 1: \(p1)")
    check(statusPage(crowd, friends: [], page: 9).hasSuffix("page 3/3: p21, p22, p23, p24, p25"), "status clamps to last page")
    check(statusPage(["ana"], friends: [], page: 1) == "online 1: ana" && statusPage([], friends: [], page: 1) == "no one online",
          "status without pages")
    check(nameColor("ana", "red") == .systemRed && nameColor("ana", nil) == nameColor("ana", "bogus"), "picked color, else from name")
    check(Set(["ana", "bob", "cy", "dee", "eli"].map { nameColor($0, nil) }).count > 1, "names spread over colors")
    check(hotKeySpec(.option, key: kVK_Space, chars: " ")! == (optionKey, "⌥Space"), "default shortcut")
    check(hotKeySpec([.control, .shift], key: kVK_ANSI_P, chars: "p")! == (controlKey | shiftKey, "⌃⇧P"), "shortcut label order")
    check(hotKeySpec([], key: kVK_ANSI_P, chars: "p") == nil && hotKeySpec(.command, key: kVK_ANSI_C, chars: "c") == nil,
          "plain and ⌘ keys refused")

    check(validName("ana_b") && !validName("a") && !validName("bad name") && !validName(String(repeating: "a", count: 21)), "name rules")
    let now = Date()
    check(nameChangeLeft(since: nil, now: now) == 0, "first name is free")
    check(nameChangeLeft(since: now.addingTimeInterval(-86400), now: now) > 12 * 86400, "rename blocked for 2 weeks")
    check(nameChangeLeft(since: now.addingTimeInterval(-15 * 86400), now: now) == 0, "rename allowed after 2 weeks")

    // End-to-end encryption
    let A = Identity(), B = Identity(), C = Identity()
    let sealed = seal("hi **there**", room: "math", from: "ana", to: ["ana": publicKey(A), "bo": publicKey(B)], with: A)!
    func read(_ ct: String = sealed.ct, _ wrap: String = sealed.wraps["bo"]!, room: String = "math", from: String = "ana",
              sender: Identity = A, as me: Identity = B) -> String? {
        open(ct: ct, wrap: wrap, room: room, from: from, senderKey: publicKey(sender), with: me)
    }
    check(sealed.wraps.keys.sorted() == ["ana", "bo"], "one locked copy per member")
    check(read() == "hi **there**", "member reads it")
    check(read(sealed.ct, sealed.wraps["ana"]!, as: A) == "hi **there**", "sender reads their own echo")
    check(read(as: C) == nil, "outsider can't read it")
    check(read(room: "art") == nil, "moving it to another room breaks it")
    check(read(from: "bo", sender: B) == nil && read(from: "eve") == nil, "relabeling the sender breaks it")
    let other = seal("evil", room: "math", from: "ana", to: ["bo": publicKey(B)], with: C)!
    check(read(other.ct) == nil, "swapping in other ciphertext breaks it")
    var pins: [String: String] = [:]
    check(pinned(&pins, "bo", publicKey(B)) && pinned(&pins, "bo", publicKey(B)), "first key is remembered")
    check(!pinned(&pins, "bo", publicKey(C)) && pins["bo"] == publicKey(B), "a different key is flagged, not swapped in")
    check(fingerprint(publicKey(A)).count == 19 && fingerprint(publicKey(A)) != fingerprint(publicKey(B)), "fingerprints")

    let k = Server(retention: 60)
    var kin: [Int: [Msg]] = [:]
    for id in 1...2 { k.add(id, send: { kin[id, default: []].append($0) }, close: {}) }
    k.handle(1, Msg(t: "hello", from: "ana", key: publicKey(A)))
    k.handle(2, Msg(t: "hello", from: "bo", key: publicKey(B)))
    let both = ["ana": publicKey(A), "bo": publicKey(B)]
    check(kin[1]?.last(where: { $0.t == "who" })?.keys == both, "online list carries keys")
    k.handle(1, Msg(t: "nick", from: "ana", key: "not a key"))
    check(k.clients[1]?.key == publicKey(A), "invalid key ignored")
    k.handle(1, Msg(t: "create", room: "x"))
    k.handle(1, Msg(t: "invite", room: "x", text: "bo"))
    k.handle(2, Msg(t: "join", room: "x"))
    check(kin[1]?.last(where: { $0.t == "members" })?.keys == both, "room members get each other's keys")
    let e2e = seal("psst", room: "x", from: "ana", to: both, with: A)!
    k.handle(1, Msg(t: "say", room: "x", ct: e2e.ct, wraps: e2e.wraps))
    let arrived = kin[2]!.last!
    check(arrived.text == nil && open(ct: arrived.ct!, wrap: arrived.wraps!["bo"]!, room: "x", from: arrived.from!,
                                      senderKey: publicKey(A), with: B) == "psst", "end to end through the host")

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
    check(!s.history.contains { $0.text == "hi" } && s.history.contains { $0.ct == "CT" }, "host erases old history")

    s.handle(3, Msg(t: "create", room: "art"))
    s.handle(3, Msg(t: "invite", room: "art", text: "ana"))
    s.handle(2, Msg(t: "leave", room: "math"))
    check(s.owners["math"] == 1 && s.clients[1]?.rooms.contains("math") == true, "a member leaving keeps the room")
    s.handle(1, Msg(t: "invite", room: "math", text: "ana2"))
    s.handle(2, Msg(t: "join", room: "math"))
    check(s.clients[2]?.rooms.contains("math") == true, "re-invited member rejoins")
    inbox[2] = []
    s.remove(1)  // ana, who made #math, quits
    check(s.clients[2]?.rooms.contains("math") == false && inbox[2]!.contains { $0.t == "left" && $0.room == "math" },
          "creator quitting closes the room for everyone")
    check(!s.history.contains { $0.room == "math" } && s.owners["math"] == nil, "closed room's history is erased")
    s.handle(3, Msg(t: "leave", room: "art"))
    check(s.owners["art"] == nil && s.invites["art"] == nil, "creator leaving closes the room and its invites")
    s.handle(2, Msg(t: "create", room: "math"))
    check(s.owners["math"] == 2, "a closed room's name is free again")

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
