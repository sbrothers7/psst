import AppKit

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

/// Swearing, slurs and sexual words. `inside`: any word containing it; `start`: any word starting with it;
/// `whole`: the word or its plural. Letters may repeat or be look-alikes (fuuuck, sh1t, @ss).
let swears: NSRegularExpression = {
    let inside = ["fuck"]
    let start = ["shit", "bullshit", "horseshit", "dipshit", "batshit", "cunt", "bitch", "bastard", "piss", "wank", "twat",
                 "slut", "whore", "porn", "jizz", "dildo", "blowjob", "handjob", "hentai", "asshole", "arsehole", "dickhead",
                 "cocksucker", "nigger", "nigga", "faggot"]
    let whole = ["ass", "arse", "dumbass", "jackass", "dick", "cock", "pussy", "pussies", "tit", "titties", "boob", "boobies",
                 "cum", "cumming", "fag", "retard", "retarded", "spic", "kike", "chink", "tranny", "trannies"]
    let look: [Character: String] = ["a": "a@4", "e": "e3", "i": "i1!", "o": "o0", "s": "s$5", "u": "uv"]
    func any(_ words: [String]) -> String {
        "(?:" + words.map { $0.map { "[" + NSRegularExpression.escapedPattern(for: look[$0] ?? String($0)) + "]+" }.joined() }
            .joined(separator: "|") + ")"
    }
    let w = "[\\p{L}\\p{N}]"
    return try! NSRegularExpression(pattern: "(?<!\(w))(?:\(w)*\(any(inside))\(w)*|\(any(start))\(w)*|\(any(whole))(?:e?s)?)(?!\(w))",
                                    options: .caseInsensitive)
}()

/// Whether the text @mentions any of these names (a username or a nickname), in any case.
func mentions(_ text: String, _ names: [String]) -> Bool {
    names.contains { n in
        !n.isEmpty && text.range(of: "(?<![\\p{L}\\p{N}_-])@" + NSRegularExpression.escapedPattern(for: n) + "(?![\\p{L}\\p{N}_-])",
                                 options: [.regularExpression, .caseInsensitive]) != nil
    }
}

/// Hides swear words behind bullets of the same length.
func censor(_ s: String) -> String {
    let out = NSMutableString(string: s)
    for m in swears.matches(in: s, range: NSRange(s.startIndex..., in: s)).reversed() {
        out.replaceCharacters(in: m.range, with: String(repeating: "•", count: out.substring(with: m.range).count))
    }
    return out as String
}
