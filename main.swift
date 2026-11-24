// Psst — tiny LAN overlay messenger for macOS. One file, no dependencies.
//
// Build: ./build.sh     Run: open Psst.app     Test: Psst.app/Contents/MacOS/Psst --selftest

import AppKit
import Network
import Carbon.HIToolbox
import CryptoKit
import ServiceManagement
import UniformTypeIdentifiers

let serviceType = "_psst._tcp"
let port: NWEndpoint.Port = 47820
let maxLine = 65536, maxText = 500, maxHistory = 500

/// TCP that also runs over peer-to-peer Wi-Fi (AWDL, what AirDrop uses): Macs within ~30 m reach each other
/// directly, even on networks that block devices from talking or have no shared network at all. Wi-Fi must be on.
/// Keepalive: a host whose lid closed, or someone who walked out of range, is noticed in ~25 s instead of never,
/// so clients reconnect (to another host if needed) and the host drops people who are gone.
func tcp() -> NWParameters {
    let t = NWProtocolTCP.Options()
    t.enableKeepalive = true
    t.keepaliveIdle = 10
    t.keepaliveInterval = 5
    t.keepaliveCount = 3
    t.connectionDropTime = 20  // unacknowledged sends give up after 20 s too
    let p = NWParameters(tls: nil, tcp: t)
    p.includePeerToPeer = true
    return p
}

// MARK: - Hosting: every Mac hosts, everyone shares the oldest
//
// Every Mac runs a host and advertises it. All Macs join the same one, the longest-running host still reachable,
// so no one has to type /host and a restarted Mac never splits the class. The host keeps the next two in line
// supplied with a copy of its rooms and recent messages; if it disappears they're elected next and carry on.
// Macs out of Wi-Fi range of the host reach it through a Mac in between (up to 3 hops).

/// A Mac as seen over Bonjour. `since` = when its host started. `up` = the host it is connected to right now
/// (maybe one this Mac can't see) and `hops` how many Macs away that is: 0 = itself, 1 = direct.
struct HostAd: Equatable { var id: String, since: Double, up = "", upSince = Double.infinity, hops = 0 }

let maxHops = 3

/// The host everyone should share: the oldest one still reachable, directly or through another Mac.
/// `down`: Macs that just failed to answer. A Mac that vanished (lid closed) stays listed for up to an hour,
/// so it's skipped, along with the host it claimed to reach.
func electHost(own: HostAd?, ads: [HostAd], down: Set<String>) -> HostAd? {
    let live = ads.filter { !down.contains($0.id) }
    var hosts = live + live.filter { !$0.up.isEmpty && $0.hops < maxHops }.map { HostAd(id: $0.up, since: $0.upSince) }
    if let own { hosts.append(own) }
    if hosts.isEmpty { hosts = ads }  // everyone failed: keep trying them
    return hosts.min { ($0.since, $0.id) < ($1.since, $1.id) }
}

enum Route: Equatable { case local, direct(HostAd), relay(HostAd) }

/// How to reach `host`: it's this Mac, it's in Wi-Fi range, or through the nearest Mac connected to it.
func route(to host: String, own: String?, ads: [HostAd], down: Set<String>) -> Route? {
    if host == own { return .local }
    if let a = ads.first(where: { $0.id == host }), !down.contains(host) { return .direct(a) }
    let relays = ads.filter { $0.up == host && $0.id != own && $0.hops < maxHops && !down.contains($0.id) }
    if let r = relays.min(by: { ($0.hops, $0.id) < ($1.hops, $1.id) }) { return .relay(r) }
    return ads.first { $0.id == host }.map { .direct($0) }  // nothing better: keep trying it
}

/// What the next host needs to carry on: rooms, who is in them (with keys, so only the same Mac gets back in),
/// invites, requests and nicknames. By name, because everyone reconnects with new connections.
struct Snapshot: Codable, Equatable {
    struct Room: Codable, Equatable {
        var owner = "", members: [String: String] = [:], invites: [String] = [], requests: [String] = [], nicks: [String: String] = [:]
        var pass: String?  // password hash, for rooms that have one
        var desc: String?  // shown when browsing rooms
        var type: Int?     // who can get in: see typeNames
    }
    var rooms: [String: Room] = [:]
}

// MARK: - Updates: signed GitHub releases

let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
let repo = "https://github.com/sbrothers7/psst"
let releases = repo + "/releases/latest/download/"  // not the API: no rate limit for a school sharing one IP
let updateKey = "Oyw6t/z9rkWjGdtYZdOm8b3eekjGoH1HCViAYbINriA="  // Ed25519 public key; the private half never leaves the release Mac (~/.config/psst/update.key)

/// "…/releases/tag/v1.4.0" → "1.4.0": github.com/…/releases/latest redirects to the latest release's tag, so a HEAD
/// request gives the version without downloading anything. nil when there's no release (it lands on /releases).
func tagVersion(_ url: URL?) -> String? {
    guard let u = url, u.pathComponents.suffix(2).first == "tag" else { return nil }
    let tag = u.lastPathComponent
    return tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
}

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
    var nick: String? = nil           // say: the sender's nickname in that room
    var nicks: [String: String]? = nil // members: name -> nickname in that room
    var counts: [String: Int]? = nil  // rooms: every open room -> how many are in it
    var since: Double? = nil          // hello: when my own host started, so the host knows who is next in line
    var snap: Snapshot? = nil         // rep: rooms, for the next host in line
    var batch: [Msg]? = nil           // rep: messages, for the next host in line
    var descs: [String: String]? = nil // rooms: room -> its description
    var pic: String? = nil            // hello/nick/pic: profile picture: "letters", a base64 JPEG or PNG, "" for none
    var types: [String: Int]? = nil   // rooms/create: room -> who can get in (see typeNames)
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

/// A room password as sent: hashed, so the typed password never leaves this Mac. Not tied to the room's name,
/// so it keeps working after /room rename.
// ponytail: anyone watching the network can replay the hash to join; it keeps people out, not eavesdroppers.
func roomPass(_ password: String) -> String {
    Data(SHA256.hash(data: Data("psst room \(password.trimmingCharacters(in: .whitespaces))".utf8))).base64EncodedString()
}

/// Room types, by number: who can get in. A room without one is 0.
let typeNames = ["invite only", "password only", "invite or password", "open access"]
let typeList = "0 invite only · 1 password only · 2 invite or password · 3 open access"

/// Words /room reads as options, so they can't name a room ("current" is the room you're in).
let reservedRooms: Set<String> = ["public", "current", "create", "set", "members"]

/// After "/room create ": [room name] [desc] [type]. A last word 0–3 is the type (default 0); quote a description that ends in a digit.
func createArgs(_ rest: String) -> (room: String, desc: String, type: Int) {
    var w = rest.split(separator: " ").map(String.init)
    let room = w.isEmpty ? "" : clean(w.removeFirst(), lower: true)
    let type = w.last.flatMap { Int($0) }.flatMap { typeNames.indices.contains($0) ? $0 : nil }
    if type != nil { w.removeLast() }
    return (room, unquote(Substring(w.joined(separator: " "))), type ?? 0)
}

/// After "/room ": [room name] set [name|desc|password|type] [new]. No room name, or "current": the room you're in.
/// nil when it isn't a set command; `field` is lowercased and may be anything (the caller checks it).
func roomEdit(_ arg: String, current: String) -> (room: String, field: String, value: String)? {
    var w = arg.split(separator: " ", maxSplits: 1).map(String.init), room = current
    if w.first?.lowercased() != "set" {
        guard w.count == 2 else { return nil }
        room = w[0].lowercased() == "current" ? current : clean(w[0], lower: true)
        w = w[1].split(separator: " ", maxSplits: 1).map(String.init)
        guard w.first?.lowercased() == "set" else { return nil }
    }
    let rest = w.count > 1 ? w[1].split(separator: " ", maxSplits: 1).map(String.init) : []
    return (room, rest.first?.lowercased() ?? "", rest.count > 1 ? rest[1].trimmingCharacters(in: .whitespaces) : "")
}

/// `"chess club"` → chess club: quotes are optional around a description.
func unquote(_ s: Substring) -> String { s.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"“”")) }

// ponytail: enforced on this Mac only; a host can't check it without accounts.
let nameCooldown: TimeInterval = 14 * 86400

/// Seconds until the name may change again (0 = now).
func nameChangeLeft(since: Date?, now: Date = Date()) -> TimeInterval {
    guard let since else { return 0 }
    return max(0, since.addingTimeInterval(nameCooldown).timeIntervalSince(now))
}

// MARK: - Name colors

let nameColors: [(name: String, color: NSColor)] = [
    ("red", .systemRed), ("orange", .systemOrange), ("yellow", .systemYellow), ("green", .systemGreen), ("mint", .systemMint),
    ("teal", .systemTeal), ("blue", .systemBlue), ("indigo", .systemIndigo), ("purple", .systemPurple), ("pink", .systemPink),
]

/// The color someone picked, else one picked from their name (the same on every Mac).
/// "jordan_k" → "JK", "alex" → "A": the letters on a picture made from a username.
func initials(_ name: String) -> String {
    let parts = name.split(whereSeparator: { $0 == "_" || $0 == "-" }).prefix(2)
    return parts.isEmpty ? String(name.prefix(1)).uppercased() : parts.map { String($0.prefix(1)).uppercased() }.joined()
}

/// Only JPEG and PNG are decoded from the network, and only small ones (see validPic).
func isImageData(_ d: Data) -> Bool { d.starts(with: [0xFF, 0xD8, 0xFF]) || d.starts(with: [0x89, 0x50, 0x4E, 0x47]) }

/// A profile picture as sent: "letters", or a small JPEG/PNG in base64. Anything else counts as no picture.
func validPic(_ s: String?) -> String {
    guard let s, s == "letters" || (s.count <= 16000 && Data(base64Encoded: s).map(isImageData) == true) else { return "" }
    return s
}

/// A round picture: the image someone set, or their initials on their name color. nil for no picture.
func avatarImage(_ pic: String, name: String, color: NSColor, side: CGFloat = 22) -> NSImage? {
    var img: NSImage?
    if pic != "letters" {
        guard let d = Data(base64Encoded: pic), isImageData(d), let i = NSImage(data: d) else { return nil }
        img = i
    }
    return NSImage(size: NSSize(width: side, height: side), flipped: false) { r in
        NSBezierPath(ovalIn: r).addClip()
        if let img { img.draw(in: r); return true }
        color.setFill()
        r.fill()
        let t = initials(name) as NSString
        let a: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: side * 0.42, weight: .semibold), .foregroundColor: NSColor.white]
        let size = t.size(withAttributes: a)
        t.draw(at: NSPoint(x: r.midX - size.width / 2, y: r.midY - size.height / 2), withAttributes: a)
        return true
    }
}

/// A chosen picture, center-cropped to a square and shrunk to 96 px, as JPEG (a few KB to send).
func squareJPEG(_ img: NSImage, px: Int = 96) -> Data? {
    guard let src = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else { return nil }
    let side = min(src.width, src.height)
    guard side > 0, let crop = src.cropping(to: CGRect(x: (src.width - side) / 2, y: (src.height - side) / 2, width: side, height: side)),
          let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
                                     hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)
    else { return nil }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSImage(cgImage: crop, size: NSSize(width: px, height: px)).draw(in: NSRect(x: 0, y: 0, width: px, height: px))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .jpeg, properties: [.compressionFactor: 0.7])
}

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

let commands: [(name: String, args: [String], help: String)] = [  // help fits one line of the guide; * = required
    ("/status", ["username"], "see who is online"),
    ("/room", ["create|set|members*"], "make a room, change one, or see who's in it"),
    ("/browse", ["room name"], "browse rooms on the network"),
    ("/join", ["room name", "password"], "switch rooms, or join with an invite or password"),
    ("/request", ["room name*"], "ask to join a room (once a minute)"),
    ("/accept", ["username|all"], "accept room join request"),
    ("/invite", ["username*"], "invite someone to this room"),
    ("/leave", [], "leave this room"),
    ("/nick", ["nickname"], "set your name in this room (blank to clear)"),
    ("/friend", ["list|add|remove*", "username"], "manage friends"),
    ("/block", ["username"], "block or unblock (blank to list)"),
    ("/history", ["on|off"], "on: keep messages and scroll back; off: they fade"),
    ("/settings", [], "open settings"),
    ("/key", ["username"], "key code to compare in person"),
    ("/trust", ["username*"], "trust someone's new key"),
    ("/quit", [], "quit Psst (⌘Q)"),
]

/// "/friend [list|add|remove]* [username]": one placeholder per parameter, written like the README; * = required.
func usage(_ c: (name: String, args: [String], help: String)) -> String {
    ([c.name] + c.args.map(placeholder)).joined(separator: " ")
}
func placeholder(_ arg: String) -> String { arg.hasSuffix("*") ? "[\(arg.dropLast())]*" : "[\(arg)]" }

/// Header shown while typing a command's arguments, with the parameter under the cursor as `focus`.
/// "/friend add b" → ("/friend [list|add|remove] [username]", "[username]", help). nil for commands without parameters.
func paramGuide(_ text: String, _ c: Ctx = Ctx()) -> (label: String, focus: String, help: String)? {
    let low = text.lowercased()
    if low.hasPrefix("/room ") { return roomGuide(String(text.dropFirst(6)), c) }
    guard text.hasPrefix("/"), let cmd = commands.first(where: { low.hasPrefix($0.name + " ") }), !cmd.args.isEmpty else { return nil }
    let typing = text.dropFirst(cmd.name.count + 1).split(separator: " ", omittingEmptySubsequences: false).count - 1
    return (usage(cmd), "[\(cmd.args[min(typing, cmd.args.count - 1)].replacingOccurrences(of: "*", with: ""))]", cmd.help)
}

/// /room does several things, so its guide follows what's typed: the format of the option picked, and what Enter would do.
func roomGuide(_ rest: String, _ c: Ctx) -> (label: String, focus: String, help: String) {
    let w = rest.split(separator: " ", omittingEmptySubsequences: false).map(String.init)  // the last word is being typed
    let first = w[0].lowercased(), here = "#" + c.room
    let createLabel = "/room create [room name]* [desc] [type]", setLabel = "/room [room name] set [name|desc|password|type]* [new]*"
    if w.count == 1 {  // an option, or the room to change
        guard !first.isEmpty, !["create", "set", "members"].contains(where: { $0.hasPrefix(first) }) else {
            return c.room == "public" ? ("/room [create|members]*", "[create|members]", "make a room, or see who's in #public")
                : ("/room [create|set|members]*", "[create|set|members]", "make a room, change \(here) (or a room you name first), or see who's in it")
        }
        let r = first == "current" ? c.room : clean(first, lower: true)
        return (setLabel, "[room name]", c.joined.contains(r) && r != "public" ? "then set, to change #\(r)" : "a room you're in, or current for \(here)")
    }
    if first == "create" {
        let name = clean(w[1], lower: true), r = "#" + name
        if w.count == 2 {
            return (createLabel, "[room name]", reservedRooms.contains(name) ? "\(r) can't be a room name"
                    : c.open[name] != nil ? "\(r) already exists: /join it instead" : "name the new room (one word)")
        }
        if let k = Int(w.last!), typeNames.indices.contains(k) {
            return (createLabel, "[type]", "\(k): \(typeNames[k])" + (k == 1 || k == 2 ? " · you'll set the password next" : ""))
        }
        return (createLabel, "[desc]", "optional: what \(r) is about, for /browse · end with a type: \(typeList)")
    }
    if first == "members" { return ("/room members", "", "who's in \(here)") }
    let s = first == "set" ? 0 : 1, r = s == 0 || first == "current" ? c.room : clean(first, lower: true)  // where set is
    if w.count == 2, s == 1 { return (setLabel, "", "set, to change #\(r)") }
    guard w[s].lowercased() == "set" else { return (setLabel, "", "set goes after the room name") }
    guard r != "public" else { return (setLabel, "[room name]", "#public can't be changed: name a room you're in") }
    guard c.joined.contains(r) else { return (setLabel, "[room name]", "you're not in #\(r): /join it first") }
    if w.count == s + 2 { return (setLabel, "[name|desc|password|type]", "what to change about #\(r)") }
    let new = w[(s + 2)...].joined(separator: " ").trimmingCharacters(in: .whitespaces), type = c.types[r] ?? 0
    switch w[s + 1].lowercased() {
    case "name":
        let n = clean(new, lower: true)
        return (setLabel, "[new]", n.isEmpty ? "#\(r)'s new name" : reservedRooms.contains(n) ? "#\(n) can't be a room name"
                : c.open[n] != nil ? "#\(n) is taken" : "renames #\(r) to #\(n)")
    case "desc": return (setLabel, "[new]", "describes #\(r) for people in /browse")
    case "password": return (setLabel, "[new]", "#\(r)'s new password" + (type == 0 || type == 3 ? " · then pick type 1 or 2 so it's used" : ""))
    case "type": return (setLabel, "[new]", "#\(r) is now \(type): \(typeNames[type])")
    default: return (setLabel, "[name|desc|password|type]", "set name, desc, password or type")
    }
}

/// A row of the typing guide. Picking it: opens `sub` (a menu, typed text untouched), runs `replace` as a command (`run`),
/// or puts `replace` in the field.
struct Suggestion { var label: String, detail = "", replace: String, dot: Bool? = nil, run = false, sub: [Suggestion]? = nil }

/// What the typing guide knows: the network as this Mac sees it.
struct Ctx {
    var me = "", room = "public"
    var roster: [String] = [], friends: [String] = [], blocked: [String] = [], changed: [String] = []
    var joined: [String] = ["public"], invited: [String] = []
    var open: [String: Int] = [:]                          // every private room on the network -> people in it
    var members: [String] = [], nicks: [String: String] = [:] // this room's people and their nicknames here
    var requests: [String] = []                            // people asking to join this room, latest last
    var locked: [String] = []                              // rooms that take a password
    var descs: [String: String] = [:]                      // room -> description
    var types: [String: Int] = [:]                         // room -> who can get in (see typeNames)
    var asks: [String: [Suggestion]] = [:]                 // questions Psst asked (a menu's title -> its answers)
}

/// What you can do to someone, after picking them from a list.
func actions(_ n: String, _ c: Ctx) -> [Suggestion] {
    guard n != c.me else { return [Suggestion(label: "show my key code", replace: "/key", run: true)] }
    guard c.roster.contains(n) || c.friends.contains(n) || c.members.contains(n) else { return [] }
    var a = [c.friends.contains(n) ? Suggestion(label: "remove friend", replace: "/friend remove \(n)", run: true)
                                   : Suggestion(label: "add friend", replace: "/friend add \(n)", run: true)]
    if c.room != "public", c.roster.contains(n), !c.members.contains(n) {
        a.append(Suggestion(label: "invite to #\(c.room)", replace: "/invite \(n)", run: true))
    }
    a.append(Suggestion(label: c.blocked.contains(n) ? "unblock" : "block", replace: "/block \(n)", run: true))
    a.append(Suggestion(label: "compare key code", replace: "/key \(n)", run: true))
    return a
}

/// Commands that, sent bare, open their list as a menu to pick from. The value is the typed text that lists it.
func listMenu(_ s: String) -> String? {
    let c = s.lowercased().split(separator: " ").joined(separator: " ")
    let lists = ["/status", "/room", "/browse", "/join", "/request", "/invite", "/block", "/friend list", "/friend add", "/friend remove"]
    return c == "/friend" ? "/friend list " : lists.contains(c) ? c + " " : nil
}

/// An open menu's rows, rebuilt from what's known now: the command's list, then each picked row's menu in turn.
/// Stops where a picked row is gone (a friend just removed), so the menu backs up instead of showing stale rows.
func menuRows(_ source: String, _ path: [String], _ c: Ctx) -> (depth: Int, title: Suggestion?, rows: [Suggestion]) {
    var out = (depth: 0, title: Suggestion?.none, rows: suggest(source, c))
    for label in path {
        guard let r = out.rows.first(where: { $0.label == label }), let sub = r.sub else { break }
        out = (out.depth + 1, r, sub)
    }
    return out
}

func suggest(_ text: String, _ c: Ctx) -> [Suggestion] {
    if let answers = c.asks[text] { return answers }
    if text.hasPrefix("#"), !text.contains(" ") {  // "#room message" sends there and switches
        let q = text.dropFirst().lowercased()
        return c.joined.filter { $0.hasPrefix(q) && $0 != q }.map { Suggestion(label: "#" + $0, replace: "#\($0) ") }
    }
    if text.hasPrefix("/") {
        let parts = text.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        let typed = parts[0].lowercased()
        guard parts.count == 2 else {  // still typing the command name
            return commands.filter { $0.name.hasPrefix(typed) }
                .map { Suggestion(label: $0.name, detail: $0.help, replace: $0.args.isEmpty ? $0.name : $0.name + " ", run: true) }  // Tab: type its parameters
        }
        guard let cmd = commands.first(where: { $0.name == typed }) else { return [] }
        let words = parts[1].split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        let token = words.last!.lowercased(), base = String(text.dropLast(words.last!.count))
        func fits(_ s: String) -> Bool { s.lowercased().hasPrefix(token) }
        func plain(_ options: [String]) -> [Suggestion] { options.filter(fits).map { Suggestion(label: $0, replace: base + $0, run: true) } }
        func people(_ names: [String], inRoom: Bool = false, tag: Bool = true) -> [Suggestion] {  // picking one opens actions
            names.filter(fits).map { n in
                Suggestion(label: (inRoom ? c.nicks[n].map { "\($0) · " } ?? "" : "") + n,
                           detail: n == c.me ? "you" : tag && c.friends.contains(n) ? "friend" : "",
                           replace: base, dot: inRoom || c.roster.contains(n), sub: actions(n, c))  // replace: the list it's in
            }
        }
        let others = c.roster.filter { $0 != c.me }
        switch (cmd.name, words.count) {
        case ("/status", 1): return people(c.roster.filter(c.friends.contains) + c.roster.filter { !c.friends.contains($0) })
        case ("/room", 1):  // an option, or a room you're in to change
            var options = [("create", "make a room")]
            if c.room != "public" {  // in public: nothing to edit offered
                options += [("set", "change #\(c.room)")] + c.joined.filter { $0 != "public" && $0 != c.room }.map { ($0, "change #\($0)") }
            }
            return options.filter { fits($0.0) }.map { Suggestion(label: $0.0, detail: $0.1, replace: base + $0.0 + ($0.0 == "create" || $0.0 == "set" ? " " : " set ")) }
                + (fits("members") ? [Suggestion(label: "members", detail: "who's in #\(c.room)", replace: base, sub: suggest(base + "members ", c))] : [])
        case ("/room", 2) where words[0].lowercased() == "members": return people(c.members, inRoom: true)
        case ("/room", _) where words[0].lowercased() != "create":  // [room name] set [name|desc|password|type] [new]
            let s = words[0].lowercased() == "set" ? 0 : 1, r = s == 0 || words[0].lowercased() == "current" ? c.room : clean(words[0], lower: true)
            let type = c.types[r] ?? 0, set = words[s].lowercased() == "set"
            switch words.count - s {
            case 1: return fits("set") ? [Suggestion(label: "set", detail: "change #\(r)", replace: base + "set ")] : []
            case 2 where set:
                let fields = [("name", "rename #\(r)"), ("desc", "describe #\(r) for /browse"), ("password", "change #\(r)'s password"),
                              ("type", "who can get in · now \(typeNames[type])")]
                return fields.filter { fits($0.0) }.map { Suggestion(label: $0.0, detail: $0.1, replace: base + $0.0 + " ") }
            case 3 where set && words[s + 1].lowercased() == "type":
                return typeNames.indices.filter { fits(String($0)) }
                    .map { Suggestion(label: "\($0)", detail: typeNames[$0] + ($0 == type ? " · now" : ""), replace: base + "\($0)", run: true) }
            default: return []
            }
        case ("/browse", 1):
            return c.open.keys.sorted().filter(fits).map { r in  // what Enter does depends on the room's type
                let type = c.types[r] ?? (c.locked.contains(r) ? 2 : 0), invited = c.invited.contains(r) && type != 1
                let can = c.joined.contains(r) || invited || type == 3
                let detail = "\(c.open[r]!) in it · " + (c.joined.contains(r) ? "you're in" : invited ? "invited" : typeNames[type]) + (c.descs[r].map { " · " + $0 } ?? "")
                if can || type == 0 { return Suggestion(label: "#" + r, detail: detail, replace: can ? "/join \(r)" : "/request \(r)", run: true) }
                if type == 1 { return Suggestion(label: "#" + r, detail: detail, replace: "/join \(r) ") }  // type the password
                return Suggestion(label: "#" + r, detail: detail, replace: base,
                                  sub: [Suggestion(label: "type the password", replace: "/join \(r) "), Suggestion(label: "ask to join", replace: "/request \(r)", run: true)])
            }
        case ("/join", 1):
            let can = Set(c.joined + c.invited.filter { c.types[$0] != 1 } + c.types.filter { $0.value == 3 }.map(\.key))
            return plain(can.sorted()) + c.locked.filter { !can.contains($0) && fits($0) }.map { Suggestion(label: $0, detail: "password", replace: base + $0 + " ") }
        case ("/request", 1): return plain(c.open.keys.sorted().filter { !c.joined.contains($0) && c.types[$0] != 1 && c.types[$0] != 3 })
        case ("/accept", 1): return plain(c.requests.reversed() + ["all"])
        case ("/invite", 1): return plain(others.filter { !c.members.contains($0) })
        case ("/block", 1): return plain(others + c.blocked.filter { !c.roster.contains($0) })
        case ("/key", 1): return plain(others)
        case ("/trust", 1): return plain(c.changed)
        case ("/history", 1): return plain(["on", "off"])
        case ("/friend", 1): return plain(["list ", "add ", "remove "])
        case ("/friend", 2) where words[0] == "list":
            return people(c.friends.filter(c.roster.contains) + c.friends.filter { !c.roster.contains($0) }, tag: false)
        case ("/friend", 2) where words[0] == "add": return plain(others.filter { !c.friends.contains($0) })
        case ("/friend", 2) where words[0] == "remove": return plain(c.friends)
        default: return []
        }
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
        var ready = false  // said hello
        var hidden = false
        var key = ""  // public key, passed on so members can encrypt to each other
        var since: Double?  // when this Mac's own host started; the oldest are next in line
        var pic = ""        // profile picture (see validPic)
        var rooms: Set<String> = ["public"]
        var nicks: [String: String] = [:]  // room -> nickname there
        let send: (Msg) -> Void
        let close: () -> Void
    }
    var clients: [Int: Client] = [:]
    var invites: [String: Set<Int>] = [:]  // room -> invited client ids
    var owners: [String: Int] = [:]        // room -> creator (-1: not back yet after a takeover); closes when they leave
    var requests: [String: [Int]] = [:]    // room -> client ids asking to join, latest last
    var lastAsk: [String: Double] = [:]    // name -> when they last asked; one request a minute
    var passwords: [String: String] = [:]  // room -> password hash; anyone who has it can join
    var descs: [String: String] = [:]      // room -> description, shown when browsing
    var types: [String: Int] = [:]         // room -> who can get in (see typeNames); none: 0, invite only
    var tried: [Int: Double] = [:]         // client -> last wrong password; one guess every 3 s
    var history: [Msg] = []
    var retention: Double
    var successors: [Int] = [], lastSnap: Snapshot?  // next in line, and what they were last sent
    var restore: [String: Snapshot.Room] = [:], lastRep = 0.0, tookOver: Double?  // copy from the host, while next in line
    var pipes: [Int: (Line, Line)] = [:]   // relayed connections: far Mac <-> its host
    var dial: ((String, Int) -> Line?)?    // opens a line toward a host (set by the app, used to relay)
    private var listener: NWListener?, timers: [Timer] = [], nextID = 0
    let id = UUID().uuidString, since = Date().timeIntervalSince1970

    init(retention: Double) { self.retention = retention }

    /// `advertise` = announce on the network (as "psst-…", never the username: everyone hosts, invisible people too).
    func start(port: NWEndpoint.Port, advertise: Bool) {
        let params = tcp()
        params.allowLocalEndpointReuse = true
        guard let l = try? NWListener(using: params, on: port) else { return NSLog("psst: can't listen on \(port)") }
        l.stateUpdateHandler = { if case .failed(let e) = $0 { NSLog("psst: listener failed: \(e)") } }
        l.newConnectionHandler = { [weak self] conn in
            guard let self else { return conn.cancel() }
            self.nextID += 1
            let id = self.nextID, line = Line(conn)
            var first = true
            line.onMsg = { [weak self, weak line] m in
                defer { first = false }
                if first, m.t == "via", let line { self?.relay(id, line, to: m.text ?? "", hops: Int(m.ts ?? 0)) } else { self?.handle(id, m) }
            }
            line.onClose = { [weak self] in self?.remove(id) }
            self.add(id, send: line.send, close: line.close)
            line.start()
        }
        l.start(queue: .main)
        listener = l
        if advertise { self.advertise(up: "", upSince: .infinity, hops: 0) }
        timers = [.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.purge() },
                  .scheduledTimer(withTimeInterval: 20, repeats: true) { [weak self] _ in  // "still here" for the next in line
                      self?.successors.forEach { self?.clients[$0]?.send(Msg(t: "rep")) } }]
    }

    /// Tells nearby Macs which host this Mac is on, so ones that can't reach it over Wi-Fi can go through here.
    func advertise(up: String, upSince: Double, hops: Int) {
        listener?.service = NWListener.Service(name: "psst-" + id.prefix(8), type: serviceType, txtRecord: NWTXTRecord(
            ["id": id, "since": String(since), "up": up, "upsince": String(upSince), "hops": String(hops)]))
    }

    func stop() {
        listener?.cancel()
        timers.forEach { $0.invalidate() }
        clients.values.forEach { $0.close() }
        clients = [:]
        pipes.values.forEach { $0.0.close(); $0.1.close() }
    }

    func add(_ id: Int, send: @escaping (Msg) -> Void, close: @escaping () -> Void) {
        clients[id] = Client(send: send, close: close)
    }

    func remove(_ id: Int) {  // disconnected or quit
        guard let gone = clients.removeValue(forKey: id) else { return }
        for (room, owner) in owners where owner == id { close(room) }
        for room in gone.rooms where owners[room] != nil { members(room) }
        for r in Array(requests.keys) { requests[r]?.removeAll { $0 == id } }
        roster()
        roomList()
        sync()
    }

    /// Passes a far Mac's traffic on toward the host it can't reach over Wi-Fi itself.
    func relay(_ id: Int, _ down: Line, to host: String, hops: Int) {
        clients[id] = nil
        guard hops < maxHops, let up = dial?(host, hops + 1) else { return down.close() }
        pipes[id] = (down, up)
        down.onMsg = { [weak up] in up?.send($0) }
        up.onMsg = { [weak down] in down?.send($0) }
        down.onClose = { [weak self, weak up] in up?.close(); self?.pipes[id] = nil }
        up.onClose = { [weak self, weak down] in down?.close(); self?.pipes[id] = nil }
    }

    /// Deletes a room: everyone in it is sent back to public, its invites and history are erased.
    func close(_ room: String) {
        send(Msg(t: "note", room: room, text: "was closed"), to: room)
        for (id, var c) in clients where c.rooms.remove(room) != nil {
            c.nicks[room] = nil
            clients[id] = c
            c.send(Msg(t: "left", room: room))
        }
        owners[room] = nil
        passwords[room] = nil
        descs[room] = nil
        types[room] = nil
        invites[room] = nil
        requests[room] = nil
        restore[room] = nil
        history.removeAll { $0.room == room }
        roomList()
    }

    // ponytail: no rate limit; one client can flood. Add a per-client token bucket here if that happens.
    func handle(_ id: Int, _ m: Msg) {
        guard var c = clients[id] else { return }
        defer { sync() }
        let room = clean(m.room ?? "public", lower: true)
        func note(_ text: String, _ r: String? = nil) { c.send(Msg(t: "note", room: r, text: text)) }

        switch m.t {
        case "hello", "nick":
            let was = c
            c.name = unique(clean(m.from ?? ""), id)
            c.hidden = m.hidden ?? false
            c.key = validKey(m.key) ?? c.key
            c.since = m.since ?? c.since
            c.pic = validPic(m.pic)
            c.ready = true
            clients[id] = c
            c.send(Msg(t: "you", from: c.name))
            if m.t == "hello" {  // everyone's pictures, once; after that only changes travel
                for o in clients.values where o.ready && !o.hidden && !o.pic.isEmpty && o.name != c.name { c.send(Msg(t: "pic", from: o.name, pic: o.pic)) }
            }
            if !c.hidden, m.t == "hello" || c.pic != was.pic || c.name != was.name || was.hidden {  // invisible: no picture either
                for o in clients.values { o.send(Msg(t: "pic", from: c.name, pic: c.pic)) }
            }
            if m.t == "hello" {
                replay("public", to: c, after: m.ts ?? 0)  // only what they haven't seen
                if tookOver == nil, !restore.isEmpty { takeOver() }
                restoreRooms(id)
                c.send(roomsMsg())
            }
            roster()
            for r in clients[id]?.rooms ?? [] where r != "public" { members(r) }

        case "say":
            guard c.rooms.contains(room) else { return }
            var out = Msg(t: "say", room: room, from: c.name, ts: Date().timeIntervalSince1970)
            out.color = nameColors.contains { $0.name == m.color } ? m.color : nil
            out.nick = c.nicks[room]
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
            successors.forEach { clients[$0]?.send(Msg(t: "rep", batch: [out])) }

        case "create":
            guard !room.isEmpty, !reservedRooms.contains(room) else { return note("#\(room) can't be a room name") }
            guard owners[room] == nil else { return note("#\(room) is taken") }
            owners[room] = id
            if let p = m.text, (1...64).contains(p.count) { passwords[room] = p }  // older Psst: a password makes it type 2
            types[room] = m.types?.values.first.flatMap { typeNames.indices.contains($0) ? $0 : nil } ?? (passwords[room] == nil ? 0 : 2)
            if let t = m.descs?.values.first.map({ String($0.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80)) }), !t.isEmpty { descs[room] = t }
            c.rooms.insert(room)
            clients[id] = c
            c.send(Msg(t: "joined", room: room))
            members(room)
            roomList()
            if types[room] == 1 || types[room] == 2, passwords[room] == nil { c.send(Msg(t: "askpass", room: room)) }
            else if passwords[room] != nil { note("anyone with the password can /join \(room) [password]", room) }

        case "join":  // by type: 0 invite, 1 password, 2 either, 3 anyone
            if room == "public" || c.rooms.contains(room) { return enter(id, room) }
            guard owners[room] != nil else { return note("no room #\(room)") }
            let type = types[room] ?? 0
            if type == 3 || (type != 1 && invites[room]?.contains(id) == true) { return enter(id, room) }
            guard type != 0 else { return note("#\(room) needs an invite: /request \(room) to ask") }
            guard let pass = passwords[room] else { return note("#\(room) has no password yet") }
            guard let p = m.text else { return note("#\(room) needs a password: /join \(room) [password]" + (type == 2 ? ", or /request \(room) to ask" : "")) }
            let now = Date().timeIntervalSince1970
            guard now - (tried[id] ?? 0) >= 3 else { return note("try again later") }
            guard p == pass else { tried[id] = now; return note("wrong password for #\(room)") }
            enter(id, room)

        case "request":
            guard owners[room] != nil else { return note("no room #\(room)") }
            guard !c.rooms.contains(room) else { return note("you're already in #\(room)") }
            if types[room] == 1 { return note("#\(room) takes a password, not requests: /join \(room) [password]") }
            if types[room] == 3 || invites[room]?.contains(id) == true { return enter(id, room) }
            let now = Date().timeIntervalSince1970, wait = 60 - (now - (lastAsk[c.name] ?? 0))
            guard wait <= 0 else { return note("try again in \(Int(wait.rounded(.up))) s") }
            lastAsk[c.name] = now
            requests[room, default: []].removeAll { $0 == id }
            requests[room, default: []].append(id)
            send(Msg(t: "request", room: room, from: c.name), to: room)
            note("asked to join #\(room)")

        case "accept":  // any member may let people in, like /invite
            guard room != "public", c.rooms.contains(room) else { return note("join the room first") }
            let asking = (requests[room] ?? []).filter { clients[$0] != nil }, who = clean(m.text ?? "")
            let picked = who == "all" ? asking : who.isEmpty ? Array(asking.suffix(1)) : asking.filter { clients[$0]?.name == who }
            guard !picked.isEmpty else {
                return note(who.isEmpty || who == "all" ? "no one is asking to join" : "\(who) isn't asking to join", room)
            }
            picked.forEach { enter($0, room) }

        case "alias":  // nickname in one private room; public keeps real names so people know who is who
            guard room != "public", c.rooms.contains(room) else { return note("nicknames are per room: /join a room first") }
            let n = clean(m.text ?? "")
            if !n.isEmpty {
                guard validName(n) else { return note("nicknames are 2–20 letters, digits, - or _", room) }
                let taken = clients.contains { $0.key != id && ($0.value.name == n || ($0.value.rooms.contains(room) && $0.value.nicks[room] == n)) }
                guard !taken else { return note("\(n) is taken", room) }
            }
            let old = c.nicks[room] ?? c.name
            c.nicks[room] = n.isEmpty ? nil : n
            clients[id] = c
            send(Msg(t: "note", room: room, text: "\(old) is now \(c.nicks[room] ?? c.name) here"), to: room)
            members(room)

        case "invite":
            let name = clean(m.text ?? "")
            guard room != "public", c.rooms.contains(room) else { return note("make a room first: /room create [room name]") }
            guard types[room] != 1 else { return note("#\(room) is password only: share the password, or /room set type 2", room) }
            guard let target = clients.first(where: { $0.value.ready && $0.value.name == name && !$0.value.hidden })
            else { return note("no one named \(name)") }  // invisible people can't be found by name either
            guard !target.value.rooms.contains(room) else { return note("\(name) is already here", room) }
            invites[room, default: []].insert(target.key)
            target.value.send(Msg(t: "invite", room: room, from: c.name))
            note("invited \(name)", room)

        case "leave":
            guard room != "public", c.rooms.contains(room) else { return }
            if owners[room] == id { return close(room) }
            c.rooms.remove(room)
            c.nicks[room] = nil
            clients[id] = c
            c.send(Msg(t: "left", room: room))
            send(Msg(t: "note", room: room, text: "\(c.name) left"), to: room)
            members(room)
            roomList()

        case "history":
            if c.rooms.contains(room) { replay(room, to: c) }

        case "rename":  // any member, like /invite; everyone in it, invited or asking follows along
            let new = clean(m.text ?? "", lower: true)
            guard room != "public", c.rooms.contains(room) else { return note("/join the room to rename it") }
            guard !new.isEmpty, !reservedRooms.contains(new) else { return note(new.isEmpty ? "/room set name [new]" : "#\(new) can't be a room name", room) }
            guard owners[new] == nil else { return note("#\(new) is taken", room) }
            func move<T>(_ d: inout [String: T]) { if let v = d.removeValue(forKey: room) { d[new] = v } }
            move(&owners); move(&passwords); move(&descs); move(&types); move(&invites); move(&requests); move(&restore)
            history.removeAll { $0.room == room }  // sealed to the old name: they'd no longer open
            var told = (invites[new] ?? []).union(requests[new] ?? [])
            for (cid, var o) in clients where o.rooms.remove(room) != nil {
                o.rooms.insert(new)
                o.nicks[new] = o.nicks.removeValue(forKey: room)
                clients[cid] = o
                told.insert(cid)
            }
            for cid in told { clients[cid]?.send(Msg(t: "renamed", room: room, text: new)) }
            send(Msg(t: "note", room: new, text: "\(c.name) renamed #\(room) to #\(new)"), to: new)
            members(new)
            roomList()

        case "desc":  // one line about the room, for people browsing
            guard room != "public", c.rooms.contains(room) else { return note("descriptions are for rooms: /join one first") }
            let t = String((m.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines).prefix(80))
            descs[room] = t.isEmpty ? nil : t
            roomList()
            send(Msg(t: "note", room: room, text: t.isEmpty ? "\(c.name) cleared the description" : "\(c.name) described the room: \(t)"), to: room)

        case "pass":  // a type that ignores passwords (0, 3): ask which type should use it
            guard room != "public", c.rooms.contains(room) else { return note("/join the room to change it") }
            guard let p = m.text, (1...64).contains(p.count) else { return note("/room set password [new]", room) }
            passwords[room] = p
            send(Msg(t: "note", room: room, text: "\(c.name) changed the password"), to: room)
            if types[room] != 1 && types[room] != 2 { c.send(Msg(t: "asktype", room: room)) }

        case "type":  // a type that needs a password, and there's none yet: ask for one
            guard room != "public", c.rooms.contains(room) else { return note("/join the room to change it") }
            guard let k = Int(m.text ?? ""), typeNames.indices.contains(k) else { return note("types: " + typeList, room) }
            types[room] = k
            if k == 1 { invites[room] = nil; requests[room] = nil }  // password only: earlier invites and requests no longer count
            roomList()
            send(Msg(t: "note", room: room, text: "\(c.name) made the room \(typeNames[k])"), to: room)
            if k == 1 || k == 2, passwords[room] == nil { c.send(Msg(t: "askpass", room: room)) }

        default: break
        }
    }

    /// Puts a client in a room (invited, rejoining, or let in after asking).
    func enter(_ id: Int, _ room: String) {
        guard var c = clients[id] else { return }
        invites[room]?.remove(id)
        requests[room]?.removeAll { $0 == id }
        if c.rooms.insert(room).inserted {
            clients[id] = c
            send(Msg(t: "note", room: room, text: "\(c.name) joined"), to: room)
            if room != "public" { members(room); roomList() }
        }
        c.send(Msg(t: "joined", room: room))
        replay(room, to: c)
    }

    // MARK: Hand-over

    /// Keeps the next two in line (the oldest other hosts among the clients, who'd be elected next) supplied with
    /// rooms and messages: a full copy when someone becomes next in line, then every change.
    func sync() {
        let next = clients.compactMap { id, c in c.since.flatMap { $0 != since ? (id, $0) : nil } }
            .sorted { ($0.1, $0.0) < ($1.1, $1.0) }.prefix(2).map(\.0)
        let snap = snapshot()
        for id in next {
            guard let c = clients[id] else { continue }
            if !successors.contains(id) {
                c.send(Msg(t: "rep", text: "reset", snap: snap))
                history.forEach { c.send(Msg(t: "rep", batch: [$0])) }
            } else if snap != lastSnap { c.send(Msg(t: "rep", snap: snap)) }
        }
        successors = next
        lastSnap = snap
    }

    func snapshot() -> Snapshot {
        var s = Snapshot()
        for (room, owner) in owners {
            var r = restore[room] ?? Snapshot.Room()  // people not back yet after a takeover stay in the copy
            r.pass = passwords[room]
            r.desc = descs[room]
            r.type = types[room]
            if let o = clients[owner] { r.owner = o.name }
            for c in clients.values where c.rooms.contains(room) && !c.key.isEmpty {
                r.members[c.name] = c.key
                r.nicks[c.name] = c.nicks[room]
            }
            r.invites = Set(r.invites + (invites[room] ?? []).compactMap { clients[$0]?.name }).sorted()
            r.requests = r.requests + (requests[room] ?? []).compactMap { clients[$0]?.name }.filter { !r.requests.contains($0) }
            s.rooms[room] = r
        }
        return s
    }

    /// While next in line: takes in the host's copy.
    func absorb(_ m: Msg) {
        lastRep = Date().timeIntervalSince1970
        if m.text == "reset" { history = []; restore = [:] }
        if let snap = m.snap { restore = snap.rooms }
        history += m.batch ?? []
        if history.count > maxHistory { history.removeFirst(history.count - maxHistory) }
    }

    /// The old host is gone and people are arriving here: its rooms come back. A copy that stopped being kept
    /// up to date over a minute ago (this Mac wasn't next in line any more) is stale and dropped.
    func takeOver() {
        let now = Date().timeIntervalSince1970
        guard now - lastRep < 60 else { restore = [:]; return }
        for (room, r) in restore where owners[room] == nil {
            owners[room] = -1; passwords[room] = r.pass; descs[room] = r.desc
            types[room] = r.type ?? (r.pass == nil ? 0 : 2)  // from an older host: a password meant type 2
        }
        tookOver = now
        roomList()
    }

    /// Puts a returning Mac back in its rooms. Only the same name with the same key gets back in.
    func restoreRooms(_ id: Int) {
        guard var c = clients[id], !c.key.isEmpty, tookOver != nil else { return }
        for (room, var r) in restore where owners[room] != nil {
            if r.members[c.name] == c.key {
                r.members[c.name] = nil
                c.rooms.insert(room)
                c.nicks[room] = r.nicks.removeValue(forKey: c.name)
                if r.owner == c.name { owners[room] = id; r.owner = "" }
                c.send(Msg(t: "joined", room: room, text: "restored"))
            }
            if r.invites.contains(c.name) { invites[room, default: []].insert(id); r.invites.removeAll { $0 == c.name } }
            if r.requests.contains(c.name) { requests[room, default: []].append(id); r.requests.removeAll { $0 == c.name } }
            restore[room] = r
        }
        clients[id] = c
        roomList()
    }

    func roomCounts() -> [String: Int] {
        Dictionary(uniqueKeysWithValues: owners.keys.map { r in (r, clients.values.filter { $0.rooms.contains(r) }.count) })
    }

    /// Everyone sees which private rooms exist and how full they are, so they can ask to join.
    func roomList() {
        let m = roomsMsg()
        for c in clients.values { c.send(m) }
    }

    /// names: rooms that take a password (what older Psst reads); types: every room's type.
    func roomsMsg() -> Msg {
        Msg(t: "rooms", names: types.filter { $0.value == 1 || $0.value == 2 }.keys.sorted(), counts: roomCounts(), descs: descs, types: types)
    }

    func send(_ m: Msg, to room: String) {
        for c in clients.values where c.rooms.contains(room) { c.send(m) }
    }

    func replay(_ room: String, to c: Client, after: Double = 0) {
        for m in history where m.room == room && (m.ts ?? 0) > after { c.send(m) }
    }

    func roster() {
        let shown = clients.values.filter { $0.ready && !$0.hidden }
        let keys = Dictionary(shown.filter { !$0.key.isEmpty }.map { ($0.name, $0.key) }, uniquingKeysWith: { a, _ in a })
        for c in clients.values { c.send(Msg(t: "who", names: shown.map(\.name).sorted(), keys: keys)) }
    }

    /// Tells a private room's members who is in it and their keys, so they can encrypt to each other.
    func members(_ room: String) {
        let inRoom = clients.values.filter { $0.rooms.contains(room) && !$0.key.isEmpty }
        send(Msg(t: "members", room: room, keys: Dictionary(inRoom.map { ($0.name, $0.key) }, uniquingKeysWith: { a, _ in a }),
                 nicks: Dictionary(inRoom.compactMap { c in c.nicks[room].map { (c.name, $0) } }, uniquingKeysWith: { a, _ in a })), to: room)
    }

    func purge() {
        let now = Date().timeIntervalSince1970
        history.removeAll { ($0.ts ?? 0) < now - retention }
        lastAsk = lastAsk.filter { now - $0.value < 60 }
        if let t = tookOver, now - t > 60 {  // a minute after taking over: rooms whose creator never came back close
            for (room, owner) in owners where owner == -1 { close(room) }
            restore = [:]
            tookOver = nil
        }
    }

    func unique(_ base: String, _ id: Int) -> String {
        let base = base.isEmpty ? "anon" : base
        var name = base, i = 2
        while clients.contains(where: { $0.key != id && $0.value.ready && $0.value.name == name }) { name = "\(base)\(i)"; i += 1 }
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
    let tabs = NSTabView(), peopleBox = NSStackView(), aboutBox = NSStackView()  // settings tabs: General is `box`
    let peopleScroll = NSScrollView(), peopleNote = NSTextField(labelWithString: "")
    let nameField = NSTextField(), nameNote = NSTextField(wrappingLabelWithString: "")
    let lockBox = NSButton(checkboxWithTitle: "Lock overlay position", target: nil, action: nil)
    let loginBox = NSButton(checkboxWithTitle: "Open Psst at login", target: nil, action: nil)
    let updateBox = NSButton(checkboxWithTitle: "Install automatically, checking", target: nil, action: nil)
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
    var openRooms: [String: Int] = [:]       // private rooms on the network -> people in each
    var locked: Set<String> = []             // rooms that take a password
    var roomDescs: [String: String] = [:]    // room -> description
    var roomTypes: [String: Int] = [:]       // room -> who can get in (see typeNames)
    var asks: [String: [Suggestion]] = [:]   // questions asked as a menu: title -> answers
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
        d.register(defaults: ["cooldown": 10.0, "retention": 600.0, "invisible": false, "invites": "everyone",
                              "color": "auto", "picKind": "none", "history": false, "autoUpdate": true, "updateEvery": 86400.0, "hotKeyCode": kVK_Space, "hotKeyMods": optionKey, "hotKeyLabel": "⌥Space",
                              "x": f.minX + 12, "y": f.minY + 12])
        buildUI()
        registerHotKey()
        if name == nil { showSettings(welcome: true) }  // first launch: pick a username before anything connects
        updateIfDue()
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
    func show(_ text: NSAttributedString) { addRow(bubble(text), mine: false, ts: Date().timeIntervalSince1970) }

    /// A chat message: the name (and picture, if they set one) above the bubble on the left; mine on the right, tinted.
    func showMessage(_ m: Msg, text: NSAttributedString) {
        let from = m.from ?? "?", mine = from == me, r = m.room ?? "public"
        let col = NSStackView()
        col.orientation = .vertical
        col.alignment = mine ? .trailing : .leading
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
            views.insert(v, at: 0)
        }
        let line = NSStackView(views: views)
        line.alignment = .bottom
        line.spacing = 6
        addRow(line, mine: mine, ts: m.ts ?? Date().timeIntervalSince1970)
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
    func addRow(_ content: NSView, mine: Bool, ts: Double) {
        let row = Row()
        row.ts = ts
        content.translatesAutoresizingMaskIntoConstraints = false
        row.addSubview(content)
        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: row.topAnchor),
            content.bottomAnchor.constraint(equalTo: row.bottomAnchor),
            mine ? content.trailingAnchor.constraint(equalTo: row.trailingAnchor) : content.leadingAnchor.constraint(equalTo: row.leadingAnchor),
            mine ? content.leadingAnchor.constraint(greaterThanOrEqualTo: row.leadingAnchor)
                 : content.trailingAnchor.constraint(lessThanOrEqualTo: row.trailingAnchor),
        ])
        let rows = stack.arrangedSubviews
        stack.insertArrangedSubview(row, at: rows.firstIndex { (($0 as? Row)?.ts ?? 0) > ts } ?? rows.count)
        row.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        while stack.arrangedSubviews.count > (history ? 300 : 8) { drop(stack.arrangedSubviews[0]) }
        fitFeed()
        if !history { fade(row) }
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

    // MARK: Input + typing guide

    @objc func toggleInput() {
        if name == nil { return showSettings(welcome: true) }
        if input.isVisible { return hideInput() }
        input.orderFrontRegardless()
        input.makeKey()
        input.makeFirstResponder(field)
        updateHints()
    }

    func hideInput() {  // an open menu stays for next time: only Esc closes it
        input.orderOut(nil)
        hints.orderOut(nil)
    }

    func windowDidResignKey(_ n: Notification) { if (n.object as? Panel) === input { hideInput() } }

    func controlTextDidChange(_ n: Notification) {
        pick = 0
        updateHints()
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy sel: Selector) -> Bool {
        let open = !suggestions.isEmpty, row = open ? suggestions[pick] : nil, text = field.stringValue
        switch sel {
        case #selector(NSResponder.moveUp(_:)) where open:
            pick = (pick + suggestions.count - 1) % suggestions.count
            updateHints()
        case #selector(NSResponder.moveDown(_:)) where open:
            pick = (pick + 1) % suggestions.count
            updateHints()
        case #selector(NSResponder.insertTab(_:)) where open:
            if row!.sub != nil { pickInto(row!) } else { accept() }
        case #selector(NSResponder.insertNewline(_:)) where NSApp.currentEvent?.modifierFlags.contains(.shift) == true:
            textView.insertNewlineIgnoringFieldEditor(nil)  // Shift+Enter: a new line in the message
        case #selector(NSResponder.insertNewline(_:)):
            if let row, row.sub != nil { pickInto(row); break }  // a person or room: what to do with them
            if let row, !row.run, row.replace != text { accept(); break }  // emoji, #room, a password still to type
            field.stringValue = ""  // commands go like messages: sent, and the field is empty again
            submit(row?.run == true ? row!.replace.trimmingCharacters(in: .whitespaces) : text)
            updateHints()
        case #selector(NSResponder.cancelOperation(_:)):
            if !text.isEmpty, open { suggestions = []; hints.orderOut(nil) }  // typing: put the guide away
            else if menu != nil, text.isEmpty {  // menus close only here, a level at a time
                if menu!.path.isEmpty { menu = nil } else {
                    let back = menu!.path.removeLast()  // highlight who we came from, wherever they are in the list now
                    pick = menuRows(menu!.source, menu!.path, guide).rows.firstIndex { $0.label == back } ?? 0
                }
                updateHints()
            } else { hideInput() }
        default:
            return false
        }
        return true
    }

    /// Opens a command's list as a menu (see listMenu).
    func openList(_ source: String) {
        (menu, pick) = ((source, []), 0)
        updateHints()
    }

    /// Opens the picked row's menu: in a menu, one level down; while typing, the list it came from with this row open.
    func pickInto(_ row: Suggestion) {
        if menu != nil, field.stringValue.isEmpty { menu!.path.append(row.label) }
        else { (menu, field.stringValue) = ((row.replace, [row.label]), "") }
        pick = 0
        updateHints()
    }

    func accept() {
        field.stringValue = suggestions[pick].replace
        field.currentEditor()?.selectedRange = NSRange(location: (field.stringValue as NSString).length, length: 0)
        pick = 0
        updateHints()
    }

    var guide: Ctx {
        Ctx(me: me, room: room, roster: roster, friends: friends, blocked: blocked, changed: changed.keys.sorted(),
            joined: ["public"] + rooms.subtracting(["public"]).sorted(), invited: invited.sorted(), open: openRooms,
            members: room == "public" ? roster : (members[room] ?? [:]).keys.sorted(), nicks: nicks[room] ?? [:],
            requests: requests[room] ?? [], locked: locked.sorted(), descs: roomDescs, types: roomTypes, asks: asks)
    }

    func updateHints() {
        fitInput()
        let typed = field.stringValue, inMenu = menu != nil && typed.isEmpty  // typing shows the guide; the menu waits
        var title: Suggestion?
        if inMenu {
            let r = menuRows(menu!.source, menu!.path, guide)
            menu!.path = Array(menu!.path.prefix(r.depth))  // a picked row that's gone: back up
            (suggestions, title) = (r.rows, r.title)
        } else { suggestions = suggest(typed, guide) }
        let format = inMenu ? nil : paramGuide(typed, guide)
        guard input.isVisible, inMenu || !suggestions.isEmpty || format != nil else { return hints.orderOut(nil) }
        pick = min(pick, max(suggestions.count - 1, 0))
        let s = NSMutableAttributedString()
        // Columns: ▸ marker | label (+ dot) | detail. Wrapped lines stay under their column instead of the left edge.
        let per = 10, start = pick / per * per, pages = (suggestions.count + per - 1) / per  // a page at a time; arrows flip
        let page = suggestions.enumerated().filter { (start..<start + per).contains($0.offset) }
        let bold = NSFont.systemFont(ofSize: 12, weight: .semibold), indent: CGFloat = 14
        let widest = page.filter { !$0.element.detail.isEmpty }.map { ($0.element.label + ($0.element.dot == nil ? "" : " ●") as NSString).size(withAttributes: [.font: bold]).width }.max() ?? 0
        let col = indent + min(widest, 190) + 16
        let rows = NSMutableParagraphStyle(), head = NSMutableParagraphStyle()
        rows.tabStops = [NSTextTab(textAlignment: .left, location: indent), NSTextTab(textAlignment: .left, location: col)]
        rows.headIndent = col
        head.firstLineHeadIndent = indent
        head.headIndent = indent
        head.paragraphSpacing = 2
        if inMenu {  // the list's command, or the picked person or room; then the way out
            let line = NSMutableAttributedString(attributedString: styled(title?.label ?? menu!.source.trimmingCharacters(in: .whitespaces), bold: true))
            if let on = title?.dot { line.append(styled(on ? " ●" : " ○", color: on ? .systemGreen : .tertiaryLabelColor)) }
            line.append(styled(title == nil ? "   esc to close" : "   esc to go back", dim: true))
            line.addAttribute(.paragraphStyle, value: head, range: NSRange(location: 0, length: line.length))
            s.append(line)
        } else if let format {  // command format, the parameter being typed in accent color
            let line = NSMutableAttributedString(attributedString: styled(format.label, dim: true))
            if let r = format.label.range(of: format.focus) {
                line.addAttributes([.foregroundColor: NSColor.controlAccentColor, .font: bold], range: NSRange(r, in: format.label))
            }
            var at = format.label.startIndex  // red star: a required parameter
            while let r = format.label.range(of: "]*", range: at..<format.label.endIndex) {
                line.addAttributes([.foregroundColor: NSColor.systemRed, .font: bold], range: NSRange(format.label.index(before: r.upperBound)..<r.upperBound, in: format.label))
                at = r.upperBound
            }
            line.append(styled("   " + format.help, dim: true))
            line.addAttribute(.paragraphStyle, value: head, range: NSRange(location: 0, length: line.length))
            s.append(line)
        }
        let body = NSMutableAttributedString()
        for (i, g) in page {
            if body.length > 0 || s.length > 0 { body.append(styled("\n")) }
            body.append(styled((i == pick ? "▸" : "") + "\t" + g.label, dim: i != pick, bold: i == pick))
            if let on = g.dot { body.append(styled(on ? " ●" : " ○", color: on ? .systemGreen : .tertiaryLabelColor)) }
            if !g.detail.isEmpty { body.append(styled("\t" + g.detail, dim: true)) }
            if i == pick, !inMenu, g.sub == nil, g.replace != typed { body.append(styled("  ⇥ tab", color: .tertiaryLabelColor)) }  // Tab completes
        }
        if inMenu, suggestions.isEmpty { body.append(styled("\n\tno one here", dim: true)) }
        if pages > 1 { body.append(styled("\n\tpage \(start / per + 1) of \(pages) · ↑↓", dim: true)) }
        body.addAttribute(.paragraphStyle, value: rows, range: NSRange(location: 0, length: body.length))
        s.append(body)
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
        if let m = menu, asks[m.source]?.contains(where: { $0.replace == s }) == true { (asks[m.source], menu) = (nil, nil) }  // answered
        if let list = listMenu(s), !suggest(list, guide).isEmpty { return openList(list) }  // empty: say so in words below
        if s.hasPrefix("#") {  // "#room message": switch to that room and send there
            let r = clean(String(parts[0].dropFirst()), lower: true)
            if r == "public" || rooms.contains(r) {
                setRoom(r)
                return arg.isEmpty ? note("now in #\(r)") : submit(arg)
            }
            if openRooms[r] != nil { return note("you're not in #\(r). /request \(r) to ask to join") }
        }
        switch parts[0] {  // these work without a host
        case "/quit": return NSApp.terminate(nil)
        case "/settings": return showSettings(welcome: false)
        case "/history":  // on: every message stays and the feed scrolls back; off: they fade. Bare: switch
            let on = arg.isEmpty ? !history : arg.lowercased() == "on"
            setHistory(on)
            if on { line?.send(Msg(t: "history", room: room)) }  // what the host still has, slotted in by time
            return
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
        guard let line, !me.isEmpty else { return note("not connected yet: looking for other Macs running Psst") }
        switch parts[0] {
        case "/room":  // create [room name] [desc] [type] · [room name] set [name|desc|password|type] [new] · members
            let what = arg.split(separator: " ").first?.lowercased() ?? ""
            if what == "create" {
                let a = createArgs(String(arg.dropFirst(6)))
                guard !a.room.isEmpty else { return note("/room create [room name] [desc] [type]") }
                guard !reservedRooms.contains(a.room) else { return note("#\(a.room) can't be a room name") }
                return line.send(Msg(t: "create", room: a.room, descs: a.desc.isEmpty ? nil : [a.room: a.desc], types: [a.room: a.type]))
            }
            if what == "members" || what.isEmpty { return note("#\(room): " + guide.members.joined(separator: ", ")) }
            guard let e = roomEdit(arg, current: room) else {
                return note("/room create [room name] · /room [room name] set [name|desc|password|type] [new] · /room members")
            }
            switch e.field {
            case "name": line.send(Msg(t: "rename", room: e.room, text: clean(e.value, lower: true)))
            case "desc": line.send(Msg(t: "desc", room: e.room, text: unquote(Substring(e.value))))
            case "password" where !e.value.isEmpty: line.send(Msg(t: "pass", room: e.room, text: roomPass(e.value)))
            case "type" where Int(e.value).map(typeNames.indices.contains) == true: line.send(Msg(t: "type", room: e.room, text: e.value))
            case "type": note("types: " + typeList)
            default: note("/room [room name] set [name|desc|password|type] [new]")
            }
        case "/browse": note(openRooms.isEmpty ? "No rooms yet. /room create [room name] to make a room." : "rooms: " + openRooms.keys.sorted().map { "#" + $0 }.joined(separator: ", "))
        case "/join":  // /join [room name] [password]
            let w = arg.split(separator: " ", maxSplits: 1).map(String.init), r = w.isEmpty ? "public" : clean(w[0], lower: true)
            if r == "public" || rooms.contains(r) { setRoom(r); note("now in #\(r)") }  // already in: just switch
            else { line.send(Msg(t: "join", room: r, text: w.count > 1 ? roomPass(w[1]) : nil)) }
        case "/request": line.send(Msg(t: "request", room: arg))
        case "/accept":  // this room if anyone is asking here, else the room of the latest request
            line.send(Msg(t: "accept", room: requests[room]?.isEmpty == false ? room : lastAsked ?? room, text: arg))
        case "/nick": line.send(Msg(t: "alias", room: room, text: arg))
        case "/invite": line.send(Msg(t: "invite", room: room, text: arg))
        case "/leave": line.send(Msg(t: "leave", room: room))
        case "/status": note(arg.isEmpty ? "online: " + roster.joined(separator: ", ") : roster.contains(clean(arg)) ? "\(clean(arg)) is online" : "no one online named \(arg)")
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
        defer { if menu != nil { updateHints() } }  // an open menu shows who's online now
        let r = m.room ?? "public", tag = r == "public" ? "" : "#\(r) ", from = m.from ?? "?"
        if blocked.contains(from), m.t == "say" || m.t == "invite" || m.t == "request" { return }
        switch m.t {
        case "you":
            me = m.from ?? ""
            attempts = 0
            fails[dialed] = nil
            status.button?.appearsDisabled = false
            server?.advertise(up: viaID, upSince: viaSince, hops: hops)  // Macs out of range can come through here
        case "rep": server?.absorb(m)  // this Mac is next in line to host
        case "who":
            roster = m.names ?? []
            learn(m.keys ?? [:])
            if settings?.isVisible == true { refreshPeople() }
        case "members":
            members[r] = m.keys ?? [:]
            nicks[r] = m.nicks ?? [:]
            requests[r]?.removeAll { m.keys?[$0] != nil }  // let in already
            learn(m.keys ?? [:])
        case "pic": pics[from] = validPic(m.pic).isEmpty ? nil : m.pic  // checked again: any Mac can host
        case "rooms": openRooms = m.counts ?? [:]; locked = Set(m.names ?? []); roomDescs = m.descs ?? [:]; roomTypes = m.types ?? [:]
        case "askpass":  // a room of mine takes a password and has none: start the command for it
            show("#\(r) needs a password: type it and press Enter", dim: true)
            if field.stringValue.isEmpty {
                field.stringValue = "/room \(r) set password "
                field.currentEditor()?.selectedRange = NSRange(location: (field.stringValue as NSString).length, length: 0)
                updateHints()
            }
        case "asktype":  // a password on a room whose type ignores it: which type should use it
            let q = "#\(r) has a password now. Convert to which type?"
            asks[q] = [1, 2].map { Suggestion(label: "\($0)", detail: typeNames[$0], replace: "/room \(r) set type \($0)", run: true) }
            openList(q)
        case "request":
            requests[r, default: []].removeAll { $0 == from }
            requests[r, default: []].append(from)
            lastAsked = r
            show("#\(r) \(from) is requesting to join. Type /accept to accept.")
        case "joined":  // "restored": back in a room after the host changed; stay in the room we were in
            rooms.insert(r)
            invited.remove(r)
            if m.text != "restored" || r == prevRoom { setRoom(r) }
        case "renamed":  // a room I'm in, invited to or asking to join has a new name
            let new = m.text ?? r
            func move<T>(_ d: inout [String: T]) { if let v = d.removeValue(forKey: r) { d[new] = v } }
            if rooms.remove(r) != nil { rooms.insert(new) }
            if invited.remove(r) != nil { invited.insert(new) }
            move(&members); move(&nicks); move(&requests)
            if lastAsked == r { lastAsked = new }
            if prevRoom == r { prevRoom = new }
            if room == r { setRoom(new) }
        case "left": rooms.remove(r); members[r] = nil; nicks[r] = nil; requests[r] = nil; if r == room { setRoom("public") }
        case "invite":
            let policy = d.string(forKey: "invites")
            guard policy == "everyone" || (policy == "friends" && friends.contains(from)) else { return }
            invited.insert(r)
            show("\(from) invited you to #\(r). /join \(r)")
        case "note": show(tag + (m.text ?? ""), dim: true)
        case "say":
            lastSeen = max(lastSeen, m.ts ?? 0)
            guard seen.insert("\(m.ts ?? 0) \(from)").inserted else { return }  // replays repeat what's on screen
            var text = m.text ?? ""
            if r != "public" {  // private: must open with the sender's trusted key, or it isn't shown
                guard let ct = m.ct, let wrap = m.wraps?[me], let key = members[r]?[from] ?? known[from], pins[from] == key,
                      let opened = open(ct: ct, wrap: wrap, room: r, from: from, senderKey: key, with: identity) else { return }
                text = opened
            }
            showMessage(m, text: markdown(text))
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

    func ad(_ r: NWBrowser.Result) -> HostAd? {  // nil: an older Psst, not part of the election
        guard case .bonjour(let t) = r.metadata, let id = t["id"], let since = t["since"].flatMap(Double.init) else { return nil }
        return HostAd(id: id, since: since, up: t["up"] ?? "", upSince: t["upsince"].flatMap(Double.init) ?? .infinity,
                      hops: t["hops"].flatMap(Int.init) ?? maxHops)
    }
    var ads: [HostAd] { hosts.compactMap(ad) }
    var down: Set<String> { Set(downUntil.filter { $0.value > Date() }.keys) }

    /// The host this Mac should be on (see electHost).
    func target() -> HostAd? { electHost(own: server.map { HostAd(id: $0.id, since: $0.since) }, ads: ads, down: down) }

    /// Opens a started line toward `host`: loopback, straight to it, or through a Mac that reaches it.
    /// Returns the Mac actually dialled (marked down if it keeps failing) and this Mac's distance to the host.
    func dial(_ host: String, hops: Int, pin: Bool = false) -> (line: Line, through: String, hops: Int)? {
        guard let r = route(to: host, own: server?.id, ads: ads, down: down) else { return nil }
        let l: Line, through: String, dist: Int
        switch r {
        case .local:
            l = Line(NWConnection(to: .hostPort(host: "127.0.0.1", port: port), using: tcp()))
            (through, dist) = (host, 0)
        case .direct(let a), .relay(let a):
            guard let res = hosts.first(where: { ad($0)?.id == a.id }) else { return nil }
            let params = tcp()
            if pin {  // a Mac is often reachable over several links (school Wi-Fi, peer-to-peer); each retry pins the next,
                      // so a network that silently drops traffic can't trap us on it
                let links: [NWInterface?] = [nil] + res.interfaces.filter { $0.type != .loopback }
                params.requiredInterface = links[attempts % links.count]
                attempts += 1
            }
            l = Line(NWConnection(to: res.endpoint, using: params))
            (through, dist) = (a.id, r == .direct(a) ? 1 : a.hops + 1)
        }
        l.start()
        if case .relay(_) = r { l.send(Msg(t: "via", text: host, ts: Double(hops))) }
        return (l, through, dist)
    }

    /// Keeps this Mac on the shared host: connects if it isn't, and moves when a better host appears,
    /// but only once that host answers, so a stale listing never pulls people off a host that works.
    func regroup() {
        guard let line else { return connect() }
        guard !me.isEmpty, let want = target(), want.id != viaID else { return }
        switch route(to: want.id, own: server?.id, ads: ads, down: down) {
        case .local?, .relay?: line.close()  // this Mac's own host answers; a relaying Mac is on it right now
        case .direct(let a)?:
            guard let res = hosts.first(where: { ad($0)?.id == a.id }) else { return }
            let probe = NWConnection(to: res.endpoint, using: tcp())
            probe.stateUpdateHandler = { [weak self] state in
                if case .ready = state, let self, self.line === line { line.close() }  // reconnect lands on `want`
            }
            probe.start(queue: .main)
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
                if case .ready = probe.state {} else { self?.downUntil[a.id] = Date() + 60 }
                probe.cancel()
            }
        case nil: break
        }
    }

    /// A Mac that slept a while gave up its place: restarting its host makes it the newest, so people stay with
    /// whoever took over instead of all moving back. Also a good moment to look for updates, if it's time.
    func onWake() {
        updateIfDue()
        if Date().timeIntervalSince(sleptAt ?? Date()) > 30 { startHost() }
    }

    func connect() {
        guard line == nil, name != nil, let host = target(), let link = dial(host.id, hops: 0, pin: true) else { return }
        (viaID, viaSince, dialed, hops) = (host.id, host.since, link.through, link.hops)
        via = hops == 0 ? "hosting here" : hops == 1 ? "host nearby" : "through \(hops - 1) Mac\(hops > 2 ? "s" : "")"
        let l = link.line
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self, weak l] in  // no answer in 8 s: try again
            if let self, let l, self.line === l, self.me.isEmpty { l.close() }
        }
        line = l
        l.onMsg = { [weak self] in self?.got($0) }
        l.onClose = { [weak self, weak l] in
            guard let self, self.line === l else { return }
            if self.me.isEmpty {  // never got in: after two misses, try other ways for a minute
                self.fails[self.dialed, default: 0] += 1
                if self.fails[self.dialed]! >= 2 { self.downUntil[self.dialed] = Date() + 60; self.fails[self.dialed] = nil }
            }
            self.server?.advertise(up: "", upSince: .infinity, hops: 0)
            self.prevRoom = self.room
            self.line = nil
            self.me = ""
            self.roster = []
            self.rooms = []
            self.invited = []
            self.openRooms = [:]
            self.roomTypes = [:]
            self.requests = [:]
            self.nicks = [:]
            self.setRoom("public")
            self.status.button?.appearsDisabled = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.connect() }
        }
        l.send(Msg(t: "hello", from: name, ts: lastSeen, hidden: d.bool(forKey: "invisible"), key: publicKey(identity),
                   since: server?.since, pic: myPic))
    }

    /// Every Mac hosts (see electHost). Restarting makes this one the newest host, e.g. after sleeping.
    func startHost() {
        server?.stop()
        let s = Server(retention: d.double(forKey: "retention"))
        s.dial = { [weak self] host, hops in self?.dial(host, hops: hops)?.line }
        s.start(port: port, advertise: true)
        server = s
        if let line { line.close() } else { connect() }
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
        add(me.isEmpty ? "Looking for other machines…" : "\(me) in #\(room) · \(via)")
        add("Write…   \(shortcut)", #selector(toggleInput))
        menu.addItem(.separator())

        add(room == "public" ? "Online (/status for options)" : "Online: click to invite to #\(room)")
        for n in roster where n != me {
            add((friends.contains(n) ? "★ " : "") + n, room == "public" ? nil : #selector(invite(_:)), n, indent: true)
        }
        menu.addItem(.separator())

        add("Settings…", #selector(openSettings))
        add("Psst \(appVersion), updates itself")
        menu.addItem(NSMenuItem(title: "Quit Psst", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    // MARK: Updates

    /// With auto update on (Settings), looks once the chosen interval has passed since the last look, across restarts.
    func updateIfDue() {
        let now = Date().timeIntervalSince1970, last = d.double(forKey: "lastUpdateCheck")
        guard d.bool(forKey: "autoUpdate"), now - last >= d.double(forKey: "updateEvery") || now < last else { return }  // now < last: clock moved back
        d.set(now, forKey: "lastUpdateCheck")
        checkForUpdate()
    }

    func checkForUpdate() {
        var head = URLRequest(url: URL(string: repo + "/releases/latest")!)
        head.httpMethod = "HEAD"
        URLSession.shared.dataTask(with: head) { _, response, _ in  // the version is where it redirects: see tagVersion
            guard let v = tagVersion(response?.url), isNewer(v, than: appVersion) else { return }
            func get(_ file: String) -> Data? { try? Data(contentsOf: URL(string: releases + file)!) }
            guard let zip = get("Psst.zip"), let sig = get("Psst.zip.sig") else { return }
            DispatchQueue.main.async { self.install(zip, sig: sig) }
        }.resume()
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
            Psst finds other Macs running it and connects on its own, no setup needed.
            Drag the bubbles to move them; right-click to lock them in place.
            """
        if welcome { tabs.selectTabViewItem(at: 0) }
        w.title = welcome ? "Welcome to Psst" : "Psst Settings"
        refreshSettings()
        refreshPeople()
        sizeSettings(w)
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
        loginBox.target = self
        loginBox.action = #selector(loginChanged)
        updateBox.target = self
        updateBox.action = #selector(updateBoxChanged)
        shortcutButton.target = self
        shortcutButton.action = #selector(recordShortcut)
        shortcutButton.title = shortcut
        popups = [
            popup("invisible", [("Show me in the online list", false), ("Invisible: hide me from the online list", true)]),
            popup("invites", [("Everyone", "everyone"), ("Friends only", "friends"), ("Nobody", "nobody")]),
            popup("cooldown", [("5 seconds", 5.0), ("10 seconds", 10.0), ("30 seconds", 30.0), ("1 minute", 60.0)]),
            popup("retention", [("1 minute", 60.0), ("10 minutes", 600.0), ("1 hour", 3600.0), ("1 day", 86400.0)]),
            popup("color", [("Auto", "auto")] + nameColors.map { ($0.name.capitalized, $0.name) }),
            popup("picKind", [("None", "none"), ("Letters from my name", "letters"), ("Choose a picture…", "image")]),
            popup("updateEvery", [("every hour", 3600.0), ("every 6 hours", 21600.0), ("every 12 hours", 43200.0), ("every day", 86400.0), ("every week", 604800.0)]),
        ]
        picPreview.widthAnchor.constraint(equalToConstant: 28).isActive = true
        picPreview.heightAnchor.constraint(equalToConstant: 28).isActive = true
        for (item, c) in zip(popups[4].itemArray.dropFirst(), nameColors) { item.image = swatch(c.color) }
        func label(_ s: String) -> NSTextField { NSTextField(labelWithString: s) }
        let updates = NSStackView(views: [updateBox, popups[6]])  // ☑ Install automatically, checking [every day]
        updates.alignment = .firstBaseline
        let grid = NSGridView(views: [
            [label("Username"), NSStackView(views: [nameField, saveButton])],
            [NSGridCell.emptyContentView, nameNote],
            [label("Name color"), popups[4]],
            [label("Profile picture"), NSStackView(views: [popups[5], picPreview])],
            [label("Chat shortcut"), shortcutButton],
            [label("Visibility"), popups[0]],
            [label("Room invites from"), popups[1]],
            [label("Messages fade after"), popups[2]],
            [label("When hosting, erase history after"), popups[3]],
            [NSGridCell.emptyContentView, lockBox],
            [NSGridCell.emptyContentView, loginBox],
            [label("Updates"), updates],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.row(at: 3).rowAlignment = .none  // picture row: centered on the preview, not the popup's baseline
        grid.row(at: 3).yPlacement = .center
        grid.rowAlignment = .firstBaseline
        grid.rowSpacing = 10
        welcomeText.preferredMaxLayoutWidth = grid.fittingSize.width  // wrap to the settings' width
        box.orientation = .vertical
        box.alignment = .leading
        box.spacing = 18
        box.addArrangedSubview(welcomeText)
        box.addArrangedSubview(grid)
        buildPeople(width: grid.fittingSize.width)
        buildAbout()
        for (title, v, centered) in [("General", box, false), ("People", peopleBox, false), ("About", aboutBox, true)] {
            let page = NSView(), item = NSTabViewItem(identifier: title)
            v.translatesAutoresizingMaskIntoConstraints = false
            page.addSubview(v)
            NSLayoutConstraint.activate(centered
                ? [v.centerXAnchor.constraint(equalTo: page.centerXAnchor), v.centerYAnchor.constraint(equalTo: page.centerYAnchor)]
                : [v.leadingAnchor.constraint(equalTo: page.leadingAnchor, constant: 20), v.topAnchor.constraint(equalTo: page.topAnchor, constant: 20)])
            item.label = title
            item.view = page
            tabs.addTabViewItem(item)
        }
        w.contentView!.addSubview(tabs)
        sizeSettings(w)
        w.center()
        return w
    }

    /// The window fits the biggest tab, so switching tabs never resizes it.
    func sizeSettings(_ w: NSWindow) {
        let fit = [box, peopleBox, aboutBox].map(\.fittingSize)
        let inner = NSSize(width: fit.map(\.width).max()! + 40, height: fit.map(\.height).max()! + 40)
        tabs.frame = NSRect(x: 0, y: 0, width: 1000, height: 1000)  // to measure the tab bar and border
        tabs.frame = NSRect(x: 12, y: 12, width: inner.width + 1000 - tabs.contentRect.width,
                            height: inner.height + 1000 - tabs.contentRect.height)
        w.setContentSize(NSSize(width: tabs.frame.width + 24, height: tabs.frame.height + 18))
    }

    func buildPeople(width: CGFloat) {
        peopleScroll.hasVerticalScroller = true
        peopleScroll.borderType = .bezelBorder
        peopleScroll.drawsBackground = false
        peopleScroll.widthAnchor.constraint(equalToConstant: width).isActive = true
        peopleScroll.heightAnchor.constraint(equalToConstant: 220).isActive = true
        let note = NSTextField(wrappingLabelWithString: "Friends and blocks are kept on this Mac only. You won't see messages or invites from people you block.")
        note.font = .systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        note.preferredMaxLayoutWidth = width
        peopleBox.orientation = .vertical
        peopleBox.alignment = .leading
        peopleBox.spacing = 10
        [peopleNote, peopleScroll, note].forEach(peopleBox.addArrangedSubview)
    }

    /// Everyone online here, plus friends and blocked people who aren't; online first.
    func refreshPeople() {
        let online = Set(roster), mine = [me, name ?? ""]
        let list = Set(roster + friends + blocked).subtracting(mine).sorted {
            (online.contains($0) ? 0 : 1, $0.lowercased()) < (online.contains($1) ? 0 : 1, $1.lowercased())
        }
        let here = roster.filter { !mine.contains($0) }.count
        peopleNote.stringValue = me.isEmpty ? "Not connected yet: looking for other Macs running Psst."
            : here == 0 ? "No one else is online on this network yet." : "\(here) online on this network"
        func small(_ s: String) -> NSTextField {
            let l = NSTextField(labelWithString: s)
            l.font = .systemFont(ofSize: 11)
            l.textColor = .secondaryLabelColor
            return l
        }
        func check(_ who: String, _ on: Bool, _ tag: Int) -> NSButton {
            let b = NSButton(checkboxWithTitle: "", target: self, action: #selector(personToggled))
            b.state = on ? .on : .off
            b.identifier = NSUserInterfaceItemIdentifier(who)
            b.tag = tag  // 0 friend, 1 blocked
            return b
        }
        let rows: [[NSView]] = list.isEmpty ? [[small("People show up here once they open Psst on this network.")]]
            : [[small("Name"), small("Friend"), small("Blocked")]] + list.map { who in
                let t = NSMutableAttributedString(string: who, attributes: [.font: NSFont.systemFont(ofSize: 13), .foregroundColor: NSColor.labelColor])
                let on = online.contains(who)
                t.append(NSAttributedString(string: on ? "  ●" : "  ○", attributes: [.font: NSFont.systemFont(ofSize: 11),
                    .foregroundColor: on ? NSColor.systemGreen : NSColor.tertiaryLabelColor]))
                return [NSTextField(labelWithAttributedString: t), check(who, friends.contains(who), 0), check(who, blocked.contains(who), 1)]
            }
        let g = NSGridView(views: rows)
        g.rowSpacing = 6
        g.columnSpacing = 24
        g.rowAlignment = .firstBaseline
        if !list.isEmpty { for c in 1...2 { g.column(at: c).xPlacement = .center } }
        g.frame = NSRect(origin: NSPoint(x: 10, y: 8), size: g.fittingSize)
        let doc = Flipped(frame: NSRect(x: 0, y: 0, width: g.frame.maxX + 10, height: g.frame.maxY + 8))
        doc.addSubview(g)
        peopleScroll.documentView = doc
    }

    @objc func personToggled(_ b: NSButton) {
        guard let who = b.identifier?.rawValue else { return }
        if b.tag == 0 { friends.removeAll { $0 == who }; if b.state == .on { friends.append(who) } }
        else { blocked.removeAll { $0 == who }; if b.state == .on { blocked.append(who) } }
    }

    func buildAbout() {
        let icon = NSImageView(image: NSApp.applicationIconImage)
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.widthAnchor.constraint(equalToConstant: 96).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 96).isActive = true
        let title = NSTextField(labelWithString: "Psst")
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        let version = NSTextField(labelWithString: "Version \(appVersion)")
        version.textColor = .secondaryLabelColor
        let credits = NSTextField(labelWithString: "by sbrothers7")
        credits.font = .systemFont(ofSize: 11)
        credits.textColor = .secondaryLabelColor
        let link = NSButton(title: "", target: self, action: #selector(openRepo))
        link.isBordered = false
        link.attributedTitle = NSAttributedString(string: repo.replacingOccurrences(of: "https://", with: ""),
                                                  attributes: [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.linkColor])
        aboutBox.orientation = .vertical
        aboutBox.alignment = .centerX
        aboutBox.spacing = 4
        [icon, title, version, NSTextField(labelWithString: "A tiny LAN chat overlay for Macs."), credits, link].forEach(aboutBox.addArrangedSubview)
        aboutBox.setCustomSpacing(10, after: icon)
        aboutBox.setCustomSpacing(14, after: version)
    }

    @objc func openRepo() { NSWorkspace.shared.open(URL(string: repo)!) }

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
        updateBox.state = d.bool(forKey: "autoUpdate") ? .on : .off
        popups[6].isEnabled = updateBox.state == .on
        if #available(macOS 13, *) { loginBox.state = SMAppService.mainApp.status == .enabled ? .on : .off } else {
            loginBox.isEnabled = false
            loginBox.title = "Open Psst at login (needs macOS 13; use System Preferences › Login Items)"
        }
        popups[4].itemArray.first?.image = swatch(nameColor(name ?? "", nil))  // what Auto gives this name
        picPreview.image = avatarImage(myPic, name: name ?? "", color: nameColor(name ?? "", d.string(forKey: "color")), side: 28)
        picPreview.isHidden = picPreview.image == nil
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
        let key = p.identifier!.rawValue, old = d.object(forKey: key)
        d.set(p.selectedItem?.representedObject, forKey: key)
        if key == "retention" { server?.retention = d.double(forKey: key); server?.purge() }
        if key == "invisible" { sendProfile() }
        if key == "color" { refreshSettings() }  // the letters picture takes the name color
        if key == "picKind" { picChanged(old: old) }
    }

    var myPic: String {  // what others see beside my messages
        switch d.string(forKey: "picKind") {
        case "letters": return "letters"
        case "image": return d.data(forKey: "picData")?.base64EncodedString() ?? ""
        default: return ""
        }
    }

    func sendProfile() { line?.send(Msg(t: "nick", from: name, hidden: d.bool(forKey: "invisible"), key: publicKey(identity), pic: myPic)) }

    /// "Choose a picture…" asks for an image; cancelling goes back to what was set before.
    func picChanged(old: Any?) {
        guard d.string(forKey: "picKind") == "image", let w = settings else { refreshSettings(); return sendProfile() }
        let o = NSOpenPanel()
        o.allowedContentTypes = [.image]
        o.beginSheetModal(for: w) { [weak self] r in
            guard let self else { return }
            if r == .OK, let url = o.url, let img = NSImage(contentsOf: url), let jpg = squareJPEG(img) { self.d.set(jpg, forKey: "picData") }
            else { self.d.set(old, forKey: "picKind") }
            self.refreshSettings()
            self.sendProfile()
        }
    }

    @objc func updateBoxChanged() {
        d.set(updateBox.state == .on, forKey: "autoUpdate")
        popups[6].isEnabled = updateBox.state == .on
        updateIfDue()
    }

    @objc func lockChanged() {
        d.set(lockBox.state == .on, forKey: "locked")
        applyLock()
    }

    @objc func saveName() {
        let first = name == nil
        let result = setName(nameField.stringValue)
        refreshSettings()
        nameNote.stringValue = result
        if first, name != nil { askLoginItem() }  // setup: once the username is picked
    }

    @objc func loginChanged() { setLoginItem(loginBox.state == .on) }

    func setLoginItem(_ on: Bool) {
        guard #available(macOS 13, *) else { return }
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            if SMAppService.mainApp.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }  // macOS wants a yes
        } catch {
            show("couldn't change Open at Login: \(error.localizedDescription)", dim: true)
        }
        refreshSettings()
    }

    func askLoginItem() {
        guard #available(macOS 13, *), SMAppService.mainApp.status != .enabled, let w = settings else { return }
        let a = NSAlert()
        a.messageText = "Open Psst when you log in?"
        a.informativeText = "Then you're reachable without starting it every day. You can change this in Settings."
        a.addButton(withTitle: "Open at Login")
        a.addButton(withTitle: "Not Now")
        a.beginSheetModal(for: w) { [weak self] r in if r == .alertFirstButtonReturn { self?.setLoginItem(true) } }
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
        if line != nil { sendProfile() } else { connect() }
        return "Saved: you're \(n). \(shortcut) to chat. Next name change in 2 weeks."
    }

    /// /friend [list|add|remove] [username]. Friends are kept on this Mac only.
    func friend(_ arg: String) -> String {
        let w = arg.split(separator: " ").map(String.init)
        let who = w.count > 1 ? clean(w[1]) : ""
        switch (w.first ?? "list", who.isEmpty) {
        case ("list", _):
            let online = friends.filter(roster.contains)
            return friends.isEmpty ? "no friends yet: /friend add [username]"
                : online.isEmpty ? "no friends online" : "friends online: " + online.joined(separator: ", ")
        case ("add", false):
            guard who != me, who != name else { return "that's you" }
            if !friends.contains(who) { friends.append(who) }
            return "added \(who) to friends" + (roster.contains(who) ? " (online now)" : "")
        case ("remove", false):
            friends.removeAll { $0 == who }
            return "removed \(who) from friends"
        default:
            return "/friend list · /friend add [username] · /friend remove [username]"
        }
    }

    @objc func invite(_ i: NSMenuItem) { line?.send(Msg(t: "invite", room: room, text: i.representedObject as? String)) }
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

    func hint(_ t: String, _ roster: [String] = [], _ rooms: [String] = []) -> [Suggestion] { suggest(t, Ctx(roster: roster, joined: rooms)) }
    check(hint("/").count == commands.count, "/ lists every command")
    check(usage(commands[0]) == "/status [username]", "parameters in square brackets")
    check(hint("/inv").first?.replace == "/invite ", "command completes with room for its argument")
    check(hint("/invite a", ["ana", "bob"]).map(\.replace) == ["/invite ana"], "/invite suggests people")
    check(hint("/join m", [], ["math", "public"]).map(\.replace) == ["/join math"], "/join suggests rooms")
    check(hint("/room create ma").isEmpty, "free argument has nothing to pick")
    check(paramGuide("/room create ma")?.label == "/room create [room name]* [desc] [type]" && paramGuide("/room create ma")?.focus == "[room name]", "guide shows format")
    check(usage(commands.first { $0.name == "/trust" }!) == "/trust [username]*" && paramGuide("/friend ")?.label == "/friend [list|add|remove]* [username]",
          "a star marks required parameters")
    let rc = Ctx(room: "art", joined: ["public", "art", "club"], open: ["art": 1, "club": 2], types: ["club": 2])
    let g = { (t: String) in paramGuide(t, rc).map { "\($0.label) | \($0.focus) | \($0.help)" } ?? "nil" }
    check(g("/room ") == "/room [create|set|members]* | [create|set|members] | make a room, change #art (or a room you name first), or see who's in it"
          && suggest("/room ", rc).map(\.replace) == ["/room create ", "/room set ", "/room club set ", "/room "]
          && suggest("/room cl", rc).map(\.replace) == ["/room club set "] && hint("/room ").map(\.label) == ["create", "members"],
          "/room: an option, or a room to change: \(suggest("/room ", rc).map(\.replace))")
    let set = "/room [room name] set [name|desc|password|type]* [new]*"
    check(g("/room set name lounge") == "\(set) | [new] | renames #art to #lounge"
          && g("/room club set name lounge") == "\(set) | [new] | renames #club to #lounge"
          && g("/room current set name club") == "\(set) | [new] | #club is taken"
          && g("/room cl") == "\(set) | [room name] | a room you're in, or current for #art"
          && g("/room club") == "\(set) | [room name] | then set, to change #club"
          && g("/room club ") == "\(set) |  | set, to change #club"
          && g("/room zoo set name x") == "\(set) | [room name] | you're not in #zoo: /join it first", "set guide: \(g("/room club set name lounge"))")
    check(g("/room set password x") == "\(set) | [new] | #art's new password · then pick type 1 or 2 so it's used"
          && g("/room club set password x") == "\(set) | [new] | #club's new password"
          && g("/room club set type ") == "\(set) | [new] | #club is now 2: invite or password"
          && suggest("/room club set type ", rc).map { "\($0.label) \($0.detail)" } == ["0 invite only", "1 password only", "2 invite or password · now", "3 open access"]
          && suggest("/room club set type ", rc).allSatisfy(\.run) && suggest("/room set ", rc).map(\.label) == ["name", "desc", "password", "type"],
          "set: fields, then types to pick")
    let cl = "/room create [room name]* [desc] [type]"
    check(g("/room create club") == "\(cl) | [room name] | #club already exists: /join it instead"
          && g("/room create current") == "\(cl) | [room name] | #current can't be a room name"
          && g("/room create chess after school 1") == "\(cl) | [type] | 1: password only · you'll set the password next"
          && g("/room create chess after") == "\(cl) | [desc] | optional: what #chess is about, for /browse · end with a type: \(typeList)",
          "create guide: \(g("/room create chess after"))")
    check(suggest("/room ", Ctx(joined: ["public", "club"])).map(\.label) == ["create", "members"]
          && paramGuide("/room ", Ctx(joined: ["public", "club"]))?.label == "/room [create|members]*", "in public: no editing offered")
    check(paramGuide("/room set name x", Ctx(joined: ["public"]))?.help == "#public can't be changed: name a room you're in", "no changing #public")
    check(createArgs("chess after school 2") == ("chess", "after school", 2) && createArgs("Chess") == ("chess", "", 0)
          && createArgs("chess \"grade 3\"") == ("chess", "grade 3", 0) && createArgs("chess 3") == ("chess", "", 3)
          && createArgs("chess 9") == ("chess", "9", 0), "create: a last word 0–3 is the type")
    let ed = { (a: String) in roomEdit(a, current: "art").map { "\($0.room)|\($0.field)|\($0.value)" } ?? "nil" }
    check(ed("set name lounge") == "art|name|lounge" && ed("club set desc after school") == "club|desc|after school"
          && ed("Current set TYPE 2") == "art|type|2" && ed("club lounge") == "nil" && ed("set") == "art||", "set: room name optional, current is this room")
    check(suggest("#q?", Ctx(asks: ["#q?": [Suggestion(label: "1", replace: "x", run: true)]])).map(\.replace) == ["x"], "a question's answers")
    check(unquote(" \"chess club\" ") == "chess club" && unquote("“quiet”") == "quiet" && unquote("plain words") == "plain words", "quotes optional")
    check(paramGuide("/friend a")?.focus == "[list|add|remove]", "guide highlights first parameter")
    check(paramGuide("/friend add b")?.focus == "[username]", "guide moves to second parameter")
    check(paramGuide("/leave ") == nil && paramGuide("/fri") == nil && paramGuide("hi") == nil, "no guide without parameters")
    check(hint("hi :fir").first?.replace == "hi 🔥", "emoji suggestions: \(hint("hi :fir").map(\.label))")
    check(hint("at 10:30").isEmpty && hint("a :x").isEmpty, "no emoji guide for times or 1 letter")
    check(hint("/friend ").map(\.replace) == ["/friend list ", "/friend add ", "/friend remove "], "/friend shows subcommands")
    check(suggest("/friend add b", Ctx(roster: ["bo", "bea"], friends: ["bo"])).map(\.replace) == ["/friend add bea"],
          "/friend add suggests people not yet friends")
    check(suggest("/friend remove ", Ctx(friends: ["bo"])).map(\.replace) == ["/friend remove bo"], "/friend remove suggests friends")
    check(suggest("/block z", Ctx(roster: ["ana"], blocked: ["zed"])).map(\.replace) == ["/block zed"], "/block suggests blocked to unblock")

    // Pickable lists: name + dot, then what to do with them
    let cx = Ctx(me: "me", room: "club", roster: ["al", "bo", "me", "zoe"], friends: ["bo", "gone"], joined: ["public", "club"],
                 invited: ["band"], open: ["club": 2, "art": 3, "band": 1], members: ["me", "zoe"], nicks: ["zoe": "Z"], requests: ["al", "bo"])
    let online = suggest("/status ", cx)
    check(online.map(\.label) == ["bo", "al", "me", "zoe"] && online.allSatisfy { $0.dot == true }, "status: friends first, all online")
    check(online[0].detail == "friend" && online[2].detail == "you" && online.allSatisfy { $0.replace == "/status " && !$0.run },
          "status rows open a menu and leave the typed text alone")
    check(suggest("/friend list ", cx).map { "\($0.label) \($0.dot!)" } == ["bo true", "gone false"], "friend list marks who is offline")
    let acts = online[1].sub ?? []  // al
    check(acts.map(\.replace) == ["/friend add al", "/invite al", "/block al", "/key al"] && acts.allSatisfy(\.run), "picking someone shows actions")
    check(suggest("/friend list ", cx).first?.sub?.first?.replace == "/friend remove bo", "friend list: pick, then remove")
    check(suggest("/friend list bo ", cx).isEmpty && suggest("/status al ", cx).isEmpty, "actions never go in the typed text")
    check(!(suggest("/room members ", cx).last?.sub ?? []).contains { $0.label.hasPrefix("invite") }, "no invite for people already here")
    check(suggest("/room members ", cx).map(\.label) == ["me", "Z · zoe"] && suggest("/room ", cx).last?.sub?.map(\.label) == ["me", "Z · zoe"]
          && menuRows("/room ", ["members", "Z · zoe"], cx).depth == 2, "members: nicknames, a menu inside /room")
    check(suggest("/browse ", cx).map(\.replace) == ["/request art", "/join band", "/join club"] && suggest("/browse ", cx).allSatisfy(\.run),
          "rooms: ask, or join when invited or already in")
    check(suggest("/accept ", cx).map(\.replace) == ["/accept bo", "/accept al", "/accept all"], "accept: latest first, then all")
    check(hint("/invite a", ["ana"]).allSatisfy(\.run) && suggest("/block ", cx).allSatisfy(\.run) && hint("/friend ").allSatisfy(\.run)
          && hint("/fri").allSatisfy(\.run), "Enter runs what's picked, like sending a message")
    check(listMenu("/friend") == "/friend list " && listMenu("/Friend  add") == "/friend add " && listMenu("/browse") == "/browse "
          && listMenu("/accept") == nil && listMenu("/room lab") == nil && listMenu("hi") == nil, "bare list commands open menus")
    let fm = menuRows("/friend list ", ["bo"], cx)
    check(fm.depth == 1 && fm.title?.label == "bo" && fm.rows.first?.replace == "/friend remove bo", "menu opens the picked row")
    check(menuRows("/friend list ", ["al"], cx).depth == 0 && menuRows("/status ", ["al", "x"], cx).depth == 1, "a row that's gone backs the menu up")
    let lk = Ctx(joined: ["public"], open: ["vault": 2], locked: ["vault"], descs: ["vault": "secrets"])
    check(suggest("/browse ", lk).first?.detail == "2 in it · invite or password · secrets" && suggest("/browse ", lk).first?.sub?.map(\.replace) == ["/join vault ", "/request vault"],
          "password rooms: type it, or ask")
    check(suggest("/join v", lk).map(\.replace) == ["/join vault "] && paramGuide("/join vault ")?.focus == "[password]", "/join asks for the password")
    check(hint("/room create lab pw").isEmpty, "/room create: nothing to pick for the password")
    check(suggest("/request ", cx).map(\.replace) == ["/request art", "/request band"], "request lists rooms not joined")
    check(suggest("#cl", cx).map(\.replace) == ["#club "] && suggest("#club", cx).isEmpty && suggest("#club hi", cx).isEmpty, "#room completes")

    check(nameColor("ana", "red") == .systemRed && nameColor("ana", nil) == nameColor("ana", "bogus"), "picked color, else from name")
    check(Set(["ana", "bob", "cy", "dee", "eli"].map { nameColor($0, nil) }).count > 1, "names spread over colors")
    check(hotKeySpec(.option, key: kVK_Space, chars: " ")! == (optionKey, "⌥Space"), "default shortcut")
    check(hotKeySpec([.control, .shift], key: kVK_ANSI_P, chars: "p")! == (controlKey | shiftKey, "⌃⇧P"), "shortcut label order")
    check(hotKeySpec([], key: kVK_ANSI_P, chars: "p") == nil && hotKeySpec(.command, key: kVK_ANSI_C, chars: "c") == nil,
          "plain and ⌘ keys refused")

    check(initials("jordan_k") == "JK" && initials("alex") == "A" && initials("a-b-c") == "AB" && initials("__") == "_", "letters picture")
    let photo = NSImage(size: NSSize(width: 300, height: 120), flipped: false) { r in NSColor.red.setFill(); r.fill(); return true }
    let jpg = squareJPEG(photo)!, jpg64 = jpg.base64EncodedString()
    check(isImageData(jpg) && NSBitmapImageRep(data: jpg)?.pixelsWide == 96 && NSBitmapImageRep(data: jpg)?.pixelsHigh == 96 && jpg64.count < 16000,
          "chosen picture becomes a small square JPEG (\(jpg64.count) chars)")
    check(validPic("letters") == "letters" && validPic(jpg64) == jpg64 && validPic("GIF89a") == ""
          && validPic(Data("GIF89a....".utf8).base64EncodedString()) == "" && validPic(String(repeating: "A", count: 20000)) == "", "only small JPEG/PNG pass")
    check(avatarImage("letters", name: "jo", color: .red) != nil && avatarImage(jpg64, name: "jo", color: .red) != nil && avatarImage("", name: "jo", color: .red) == nil,
          "pictures draw, no picture draws nothing")
    let pv = Server(retention: 60)
    var pvin: [Int: [Msg]] = [:]
    for id in 1...3 { pv.add(id, send: { pvin[id, default: []].append($0) }, close: {}) }
    pv.handle(1, Msg(t: "hello", from: "ann", pic: "letters"))
    pv.handle(2, Msg(t: "hello", from: "ben", pic: "not a picture"))
    pv.handle(3, Msg(t: "hello", from: "cat", hidden: true, pic: jpg64))
    check(pvin[2]!.contains { $0.t == "pic" && $0.from == "ann" && $0.pic == "letters" } && pvin[1]!.contains { $0.t == "pic" && $0.from == "ben" && $0.pic == "" },
          "everyone gets pictures; a bad one is no picture")
    check(!pvin.values.joined().contains { $0.t == "pic" && $0.from == "cat" }, "invisible people's pictures stay home")
    pv.handle(1, Msg(t: "nick", from: "ann", pic: ""))
    check(pvin[2]!.last(where: { $0.t == "pic" })?.pic == "", "removing a picture reaches everyone")

    check(validName("ana_b") && !validName("a") && !validName("bad name") && !validName(String(repeating: "a", count: 21)), "name rules")
    let now = Date()
    check(nameChangeLeft(since: nil, now: now) == 0, "first name is free")
    check(nameChangeLeft(since: now.addingTimeInterval(-86400), now: now) > 12 * 86400, "rename blocked for 2 weeks")
    check(nameChangeLeft(since: now.addingTimeInterval(-15 * 86400), now: now) == 0, "rename allowed after 2 weeks")

    // Join requests, /accept, room nicknames
    let q = Server(retention: 60)
    var qin: [Int: [Msg]] = [:]
    for (id, n) in [(1, "own"), (2, "ann"), (3, "ben"), (4, "cat"), (5, "dan")] {
        q.add(id, send: { qin[id, default: []].append($0) }, close: {})
        q.handle(id, Msg(t: "hello", from: n, key: publicKey(Identity())))
    }
    func inClub(_ id: Int) -> Bool { q.clients[id]?.rooms.contains("club") == true }
    q.handle(1, Msg(t: "create", room: "club"))
    check(qin[5]?.last?.t == "rooms" && qin[5]?.last?.counts == ["club": 1], "everyone sees open rooms")
    q.handle(2, Msg(t: "request", room: "club"))
    check(qin[1]?.last?.t == "request" && qin[1]?.last?.from == "ann", "members hear the request")
    q.handle(2, Msg(t: "request", room: "club"))
    check(qin[2]?.last?.text?.hasPrefix("try again in") == true, "one request a minute")
    q.handle(3, Msg(t: "request", room: "club"))
    q.handle(1, Msg(t: "accept", room: "club"))
    check(inClub(3) && !inClub(2), "/accept lets in whoever asked last")
    q.handle(4, Msg(t: "request", room: "club"))
    q.handle(5, Msg(t: "request", room: "club"))
    q.handle(3, Msg(t: "accept", room: "club", text: "ann"))
    check(inClub(2) && !inClub(4) && !inClub(5), "/accept name, by any member")
    q.handle(1, Msg(t: "accept", room: "club", text: "all"))
    check(inClub(4) && inClub(5) && q.requests["club"] == [], "/accept all")
    check(qin[1]?.last(where: { $0.t == "rooms" })?.counts == ["club": 5], "room sizes stay current")
    q.handle(1, Msg(t: "accept", room: "club"))
    check(qin[1]?.last?.text == "no one is asking to join", "nothing to accept")
    q.handle(2, Msg(t: "alias", room: "club", text: "Ace"))
    q.handle(3, Msg(t: "alias", room: "club", text: "Ace"))
    q.handle(4, Msg(t: "alias", room: "club", text: "own"))
    check(q.clients[2]?.nicks["club"] == "Ace" && q.clients[3]?.nicks["club"] == nil && q.clients[4]?.nicks["club"] == nil,
          "nicknames are unique and can't be someone's name")
    q.handle(2, Msg(t: "say", room: "club", ct: "C", wraps: [:]))
    check(qin[1]?.last?.nick == "Ace" && qin[1]?.last?.from == "ann", "messages carry the room nickname")
    check(qin[1]?.last(where: { $0.t == "members" })?.nicks == ["ann": "Ace"], "members list carries nicknames")
    q.handle(2, Msg(t: "alias", room: "public", text: "Zed"))
    check(q.clients[2]?.nicks["public"] == nil, "no nicknames in public")
    q.handle(2, Msg(t: "leave", room: "club"))
    check(q.clients[2]?.nicks["club"] == nil, "leaving drops the nickname")
    q.handle(1, Msg(t: "leave", room: "club"))
    check(qin[5]?.last(where: { $0.t == "rooms" })?.counts == [:], "closed rooms leave the list")

    // Room passwords
    let pw = roomPass("hunter2")
    check(pw != "hunter2" && pw == roomPass(" hunter2 ") && pw != roomPass("hunter3"), "password is hashed")
    func inVault(_ id: Int) -> Bool { q.clients[id]?.rooms.contains("vault") == true }
    q.handle(1, Msg(t: "create", room: "vault", text: pw))
    check(qin[5]?.last(where: { $0.t == "rooms" })?.names == ["vault"], "everyone sees which rooms take a password")
    q.handle(5, Msg(t: "join", room: "vault"))
    check(!inVault(5) && qin[5]?.last?.text?.contains("needs a password") == true, "no password, no entry")
    q.handle(5, Msg(t: "join", room: "vault", text: roomPass("nope")))
    check(!inVault(5) && qin[5]?.last?.text == "wrong password for #vault", "wrong password refused")
    q.handle(5, Msg(t: "join", room: "vault", text: pw))
    check(!inVault(5), "one guess every 3 seconds")
    q.tried[5]! -= 3
    q.handle(5, Msg(t: "join", room: "vault", text: pw))
    check(inVault(5) && q.snapshot().rooms["vault"]?.pass == pw, "right password gets in; the next host keeps it")
    q.handle(5, Msg(t: "desc", room: "vault", text: "  secrets  "))
    check(qin[1]?.last(where: { $0.t == "rooms" })?.descs == ["vault": "secrets"] && q.snapshot().rooms["vault"]?.desc == "secrets",
          "a member describes the room; everyone browsing sees it")
    q.handle(3, Msg(t: "desc", room: "vault", text: "hijack"))
    check(q.descs["vault"] == "secrets", "only members can describe a room")
    q.handle(4, Msg(t: "create", room: "den", descs: ["den": "  quiet corner  "]))
    check(q.descs["den"] == "quiet corner" && q.passwords["den"] == nil, "description when making a room, no password")
    q.lastAsk = [:]  // everyone asked to join #club under a minute ago
    q.handle(3, Msg(t: "request", room: "vault"))
    q.handle(5, Msg(t: "rename", room: "vault", text: "den"))
    check(q.owners["den"] == 4 && q.clients[1]?.rooms.contains("vault") == true, "can't rename onto a taken name")
    q.handle(3, Msg(t: "rename", room: "vault", text: "Safe"))
    check(q.owners["safe"] == nil && q.owners["vault"] == 1, "only members rename")
    q.handle(5, Msg(t: "rename", room: "vault", text: "Safe"))
    check(q.owners["safe"] == 1 && q.owners["vault"] == nil && q.passwords["safe"] == pw && q.descs["safe"] == "secrets"
          && q.clients[1]?.rooms.contains("safe") == true && q.clients[5]?.rooms.contains("vault") == false && q.requests["safe"] == [3],
          "rename moves the room, its password, description, members and requests")
    check([1, 3, 5].allSatisfy { id in qin[id]!.contains { $0.t == "renamed" && $0.room == "vault" && $0.text == "safe" } }
          && qin[1]?.last(where: { $0.t == "rooms" })?.counts?["safe"] == 2, "members and people asking hear the new name")
    q.tried[2] = nil
    q.handle(2, Msg(t: "join", room: "safe", text: pw))
    check(q.clients[2]?.rooms.contains("safe") == true, "the password still works after a rename")
    q.handle(4, Msg(t: "leave", room: "den"))
    q.handle(1, Msg(t: "leave", room: "safe"))
    check(q.passwords["safe"] == nil && q.descs["safe"] == nil && qin[5]?.last(where: { $0.t == "rooms" })?.names == [], "closing drops the password")

    // Room types: 0 invite only, 1 password only, 2 invite or password, 3 open access
    let ty = Server(retention: 60)
    var tin: [Int: [Msg]] = [:]
    for (id, n) in [(1, "ana"), (2, "bo"), (3, "cy")] {
        ty.add(id, send: { tin[id, default: []].append($0) }, close: {})
        ty.handle(id, Msg(t: "hello", from: n))
    }
    func inT(_ id: Int, _ r: String) -> Bool { ty.clients[id]?.rooms.contains(r) == true }
    ty.handle(1, Msg(t: "create", room: "Current"))
    ty.handle(1, Msg(t: "create", room: "set"))
    check(ty.owners.isEmpty && tin[1]?.last?.text == "#set can't be a room name", "reserved words can't name a room")
    ty.handle(1, Msg(t: "create", room: "inv"))
    check(ty.types["inv"] == 0, "rooms are invite only by default")
    ty.handle(1, Msg(t: "pass", room: "inv", text: pw))
    check(tin[1]?.last?.t == "asktype" && ty.types["inv"] == 0, "a password on an invite-only room asks which type uses it")
    ty.handle(2, Msg(t: "join", room: "inv", text: pw))
    check(!inT(2, "inv"), "type 0 ignores the password")
    ty.handle(1, Msg(t: "type", room: "inv", text: "2"))
    ty.handle(2, Msg(t: "join", room: "inv", text: pw))
    check(inT(2, "inv") && tin[3]?.last(where: { $0.t == "rooms" })?.types?["inv"] == 2, "type 2: the password gets in; everyone sees the type")
    ty.handle(1, Msg(t: "create", room: "pw", types: ["pw": 1]))
    check(tin[1]?.last?.t == "askpass" && tin[3]?.last(where: { $0.t == "rooms" })?.names == ["inv", "pw"], "type 1 asks for a password")
    ty.handle(1, Msg(t: "invite", room: "pw", text: "cy"))
    ty.handle(3, Msg(t: "request", room: "pw"))
    ty.handle(3, Msg(t: "join", room: "pw"))
    check(!inT(3, "pw") && ty.invites["pw"] == nil && ty.requests["pw"] == nil, "type 1: no invites, no requests")
    ty.handle(1, Msg(t: "pass", room: "pw", text: pw))
    check(tin[1]?.last?.t != "asktype", "type 1 already uses the password")
    ty.handle(1, Msg(t: "type", room: "pw", text: "3"))
    ty.handle(3, Msg(t: "join", room: "pw"))
    check(inT(3, "pw"), "type 3: anyone gets in")
    ty.handle(1, Msg(t: "type", room: "pw", text: "7"))
    check(ty.types["pw"] == 3, "only types 0–3")
    ty.handle(3, Msg(t: "rename", room: "pw", text: "current"))
    check(ty.owners["pw"] != nil, "can't rename to a reserved word")
    ty.handle(3, Msg(t: "rename", room: "pw", text: "hall"))
    check(ty.types["hall"] == 3 && ty.snapshot().rooms["hall"]?.type == 3, "rename keeps the type; the next host gets it")

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

    // Hand-over: the next host in line keeps a copy, and people get their rooms back when it takes over
    let h = Server(retention: 600), next = Server(retention: 600)
    var hin: [Int: [Msg]] = [:]
    let K = (0..<4).map { _ in publicKey(Identity()) }
    for id in 1...4 { h.add(id, send: { m in hin[id, default: []].append(m); if id == 2, m.t == "rep" { next.absorb(m) } }, close: {}) }
    h.handle(1, Msg(t: "hello", from: "hana", key: K[0], since: h.since))  // the host's own Mac
    h.handle(2, Msg(t: "hello", from: "nell", key: K[1], since: 50))
    h.handle(3, Msg(t: "hello", from: "ollie", key: K[2], since: 70))
    h.handle(4, Msg(t: "hello", from: "pia", key: K[3], since: 90))
    check(h.successors == [2, 3], "the two oldest other hosts are next in line, never the host itself")
    h.handle(3, Msg(t: "create", room: "lab", text: "PW"))
    h.handle(3, Msg(t: "invite", room: "lab", text: "nell"))
    h.handle(2, Msg(t: "join", room: "lab"))
    h.handle(2, Msg(t: "alias", room: "lab", text: "Nn"))
    h.handle(3, Msg(t: "invite", room: "lab", text: "pia"))
    h.handle(1, Msg(t: "create", room: "gym"))  // made by the host's own user, who leaves with the host
    h.handle(1, Msg(t: "say", text: "before"))
    h.handle(3, Msg(t: "say", room: "lab", ct: "LAB", wraps: [:]))
    let lab = next.restore["lab"]
    check(lab?.members == ["nell": K[1], "ollie": K[2]] && lab?.owner == "ollie" && lab?.invites == ["pia"] && lab?.nicks == ["nell": "Nn"] && lab?.pass == "PW",
          "next in line has the rooms: \(String(describing: lab))")
    check(next.history.contains { $0.text == "before" } && next.history.contains { $0.ct == "LAB" }, "next in line has the messages")
    let seen = next.history.first { $0.text == "before" }?.ts
    var nin: [Int: [Msg]] = [:]
    for id in 1...4 { next.add(id, send: { nin[id, default: []].append($0) }, close: {}) }
    next.handle(1, Msg(t: "hello", from: "nell", ts: seen, key: K[1], since: next.since))  // the old host is gone
    check(next.clients[1]?.rooms.contains("lab") == true && next.clients[1]?.nicks["lab"] == "Nn"
          && nin[1]!.contains { $0.t == "joined" && $0.text == "restored" }, "back in the room after the host changed")
    check(next.passwords["lab"] == "PW" && next.types["lab"] == 2, "room password and type carry over")
    check(!nin[1]!.contains { $0.text == "before" }, "no repeats of messages already seen")
    next.handle(2, Msg(t: "hello", from: "ollie", key: publicKey(Identity())))
    check(next.clients[2]?.rooms.contains("lab") == false && next.owners["lab"] == -1, "same name from another Mac doesn't get in")
    next.remove(2)
    next.handle(3, Msg(t: "hello", from: "ollie", key: K[2]))
    check(next.clients[3]?.rooms.contains("lab") == true && next.owners["lab"] == 3, "the creator gets the room back")
    next.handle(4, Msg(t: "hello", from: "pia", key: K[3]))
    next.handle(4, Msg(t: "join", room: "lab"))
    check(next.clients[4]?.rooms.contains("lab") == true, "invites carry over")
    next.tookOver! -= 61
    next.purge()
    check(next.owners["gym"] == nil && next.owners["lab"] == 3, "a minute on, rooms whose creator never came back close")
    h.remove(2)
    check(h.successors == [3, 4] && hin[4]!.contains { $0.t == "rep" && $0.text == "reset" }, "a new next in line gets a full copy")
    let stale = Server(retention: 600)
    stale.absorb(Msg(t: "rep", text: "reset", snap: h.snapshot()))
    stale.lastRep -= 120
    stale.add(1, send: { _ in }, close: {})
    stale.handle(1, Msg(t: "hello", from: "ollie", key: K[2]))
    check(stale.clients[1]?.rooms == ["public"] && stale.restore.isEmpty, "an out-of-date copy is dropped")

    // Electing one host and finding a way to it
    let hA = HostAd(id: "a", since: 100), hB = HostAd(id: "b", since: 200)
    let hC = HostAd(id: "c", since: 300, up: "a", upSince: 100, hops: 1), hD = HostAd(id: "d", since: 400, up: "a", upSince: 100, hops: 2)
    check(electHost(own: hB, ads: [hB, hA], down: []) == hA && electHost(own: hA, ads: [hB], down: []) == hA, "everyone picks the oldest host")
    check(electHost(own: hB, ads: [hB, hC], down: []) == HostAd(id: "a", since: 100), "even one only seen through another Mac")
    check(electHost(own: hB, ads: [hA, hC], down: ["a", "c"]) == hB, "skips Macs that stopped answering, and what they claimed")
    check(electHost(own: nil, ads: [hA], down: ["a"]) == hA, "everyone failed: keep trying")
    check(electHost(own: hB, ads: [HostAd(id: "e", since: 9, up: "z", upSince: 1, hops: maxHops)], down: [])?.id == "e",
          "hosts too many hops away don't count")
    check(route(to: "b", own: "b", ads: [hA], down: []) == .local && route(to: "a", own: "b", ads: [hA, hC], down: []) == .direct(hA),
          "this Mac, or straight there")
    check(route(to: "a", own: "b", ads: [hA, hD, hC], down: ["a"]) == .relay(hC), "out of reach: through the nearest Mac on it")
    check(route(to: "a", own: "b", ads: [hC], down: ["c"]) == nil && route(to: "a", own: "b", ads: [hA], down: ["a"]) == .direct(hA),
          "no way, or only a failing one")

    // Real connections over loopback, on test ports (the real one would reach a running Psst)
    let testPort: NWEndpoint.Port = 47831, relayPort: NWEndpoint.Port = 47832
    let net = Server(retention: 60), mid = Server(retention: 60)
    var dials = 0
    mid.dial = { host, _ in
        dials += 1
        guard host == net.id else { return nil }
        let l = Line(NWConnection(to: .hostPort(host: "127.0.0.1", port: testPort), using: tcp()))
        l.start()
        return l
    }
    net.start(port: testPort, advertise: false)
    mid.start(port: relayPort, advertise: false)
    RunLoop.main.run(until: Date() + 0.3)
    func talk(_ p: NWEndpoint.Port, _ out: [Msg], wait: Double = 3, until done: @escaping ([Msg]) -> Bool) -> [Msg] {
        var got: [Msg] = []
        let l = Line(NWConnection(to: .hostPort(host: "127.0.0.1", port: p), using: .tcp))
        l.onMsg = { got.append($0) }
        l.start()
        out.forEach { l.send($0) }
        let deadline = Date() + wait
        while !done(got), Date() < deadline { RunLoop.main.run(until: Date() + 0.05) }
        l.close()
        return got
    }
    let ping = "ping 👍🏽 한국어 é 👨‍👩‍👧"
    let direct = talk(testPort, [Msg(t: "hello", from: "net"), Msg(t: "say", text: ping)]) { $0.contains { $0.text == ping } }
    check(direct.first?.from == "net", "tcp hello")
    check(direct.contains { $0.text == ping }, "tcp say keeps unicode intact")
    let far = talk(relayPort, [Msg(t: "via", text: net.id, ts: 0), Msg(t: "hello", from: "far"), Msg(t: "say", text: "hi from afar")]) {
        $0.contains { $0.text == "hi from afar" }
    }
    check(far.contains { $0.t == "you" && $0.from == "far" } && far.contains { $0.text == "hi from afar" },
          "a far Mac reaches the host through one in between")
    check(mid.clients.isEmpty, "the Mac in between only passes traffic on")
    let tooFar = talk(relayPort, [Msg(t: "via", text: net.id, ts: Double(maxHops)), Msg(t: "hello", from: "x")], wait: 0.5) { _ in false }
    check(dials == 1 && !tooFar.contains { $0.t == "you" }, "relaying stops after \(maxHops) hops")
    net.stop()
    mid.stop()

    let key = Curve25519.Signing.PrivateKey(), blob = Data("zip bytes".utf8)
    let sig = Data(try! key.signature(for: blob).base64EncodedString().utf8)
    let pub = key.publicKey.rawRepresentation.base64EncodedString()
    check(verified(blob, sig: sig, key: pub), "signed update verifies")
    check(!verified(Data("tampered".utf8), sig: sig, key: pub), "tampered update rejected")
    check(!verified(blob, sig: sig, key: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()),
          "update signed by another key rejected")
    let tcpOpts = tcp().defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options
    check(tcpOpts?.enableKeepalive == true && tcp().includePeerToPeer, "keepalive notices dead links; peer-to-peer stays on")
    check(NWTXTRecord(["id": "x", "since": "12.5"])["since"].flatMap(Double.init) == 12.5, "host start time survives the TXT record")
    check(tagVersion(URL(string: "https://github.com/sbrothers7/psst/releases/tag/v1.4.0")) == "1.4.0"
          && tagVersion(URL(string: "https://github.com/sbrothers7/psst/releases")) == nil && tagVersion(nil) == nil, "version from the latest release's tag")
    check(isNewer("1.10", than: "1.9") && isNewer("1.3.1", than: "1.3") && isNewer("1.4", than: "1.3.1") && isNewer("1.0\n", than: "0") && !isNewer("1.2", than: "1.2") && !isNewer("1.1", than: "1.2"),
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
