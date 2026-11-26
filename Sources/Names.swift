import CryptoKit
import Foundation

// MARK: - Names and rooms

/// Names and room names: letters, digits, - and _, max 20 chars.
func clean(_ s: String, lower: Bool = false) -> String {
    let ok = s.filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
    return String((lower ? ok.lowercased() : ok).prefix(20))
}

/// Why a username or nickname can't be used, or nil. No swearing, also run together as in BigDick or dick_69.
func nameProblem(_ n: String) -> String? {
    guard (2...20).contains(n.count), clean(n) == n else { return "Names are 2–20 letters, digits, - or _." }
    let words = n.replacingOccurrences(of: "(?<=\\p{Ll})(?=\\p{Lu})|[^\\p{L}]+", with: " ", options: .regularExpression)
    return censor(n) == n && censor(words) == words ? nil : "That name isn't allowed."
}

func validName(_ n: String) -> Bool { nameProblem(n) == nil }

/// Each Mac picks a 4-digit tag once and keeps it, so two anas show as ana#0412 and ana#7731. Hosts pass it on.
// ponytail: tells people apart, doesn't prove who's who (anyone can pick any tag); /key and /trust do that.
func validTag(_ t: String?) -> String? { t.flatMap { $0.count == 4 && $0.allSatisfy { $0.isASCII && $0.isNumber } ? $0 : nil } }
func newTag() -> String { String(format: "%04d", Int.random(in: 0...9999)) }

/// "ana#0412" → ("ana", "0412"); an untagged name (from an older Psst) → ("ana", nil).
func splitTag(_ handle: String) -> (name: String, tag: String?) {
    guard let i = handle.firstIndex(of: "#") else { return (handle, nil) }
    return (String(handle[..<i]), String(handle[handle.index(after: i)...]))
}

/// A username as typed in a command: name, or name#tag.
func cleanHandle(_ s: String) -> String {
    let p = splitTag(s.trimmingCharacters(in: .whitespaces)), tag = (p.tag ?? "").filter { $0.isASCII && $0.isNumber }.prefix(4)
    return clean(p.name) + (tag.isEmpty ? "" : "#" + tag)
}

/// Who a typed username means among `names`: that exact name#tag, else everyone with that name (several: ask which one).
/// No one: just the typed name, cleaned.
func whoIs(_ typed: String, among names: [String]) -> [String] {
    let t = cleanHandle(typed), low = t.lowercased()
    if names.contains(t) { return [t] }
    let hits = Set(names.filter { $0.lowercased() == low || (!t.contains("#") && splitTag($0).name.lowercased() == low) })
    return hits.isEmpty ? [t] : hits.sorted()
}

func whichOne(_ names: [String]) -> String { "which one? " + names.joined(separator: ", ") }

/// A nickname I give a friend, seen only on this Mac: letters, digits, spaces and - _ ' ., 20 at most.
func friendAlias(_ raw: String) -> String {
    let kept = raw.filter { $0.isLetter || $0.isNumber || " -_'.".contains($0) }
    return String(kept.split(separator: " ").joined(separator: " ").prefix(20)).trimmingCharacters(in: .whitespaces)
}

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
let reservedRooms: Set<String> = ["public", "current", "create", "set", "member", "c"]  // c: /r c is /room create

/// After "/room create ": [room name] [type] [desc]. A second word 0–3 is the type (default 0); quote a description that starts with one.
func createArgs(_ rest: String) -> (room: String, desc: String, type: Int) {
    var w = rest.split(separator: " ").map(String.init)
    let room = w.isEmpty ? "" : clean(w.removeFirst(), lower: true)
    let type = w.first.flatMap { Int($0) }.flatMap { typeNames.indices.contains($0) ? $0 : nil }
    if type != nil { w.removeFirst() }
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
