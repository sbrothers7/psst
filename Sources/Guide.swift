import AppKit

// MARK: - Typing guide

let commands: [(name: String, args: [String], help: String)] = [  // help fits one line of the guide; * = required
    ("/online", ["username"], "see who is online"),
    ("/status", ["0|1|2"], "0 online · 1 do not disturb · 2 invisible"),
    ("/ping", ["username*"], "flash your name on their screen (once every 30 s)"),
    ("/room", ["create|set|member*"], "make a room, change one, or see who's in it · /r, /r c"),
    ("/browse", ["room name"], "browse rooms on the network"),
    ("/join", ["room name", "password"], "switch rooms, or join with an invite or password · /j"),
    ("/request", ["room name*"], "ask to join a room (once a minute) · /rq"),
    ("/accept", ["username|all"], "accept room join request · /a"),
    ("/invite", ["username*"], "invite someone to this room · /i"),
    ("/leave", ["silent"], "leave this room; silent: without telling it"),
    ("/nick", ["nickname"], "set your name in this room (blank to clear)"),
    ("/friend", ["list|add|remove|rename*", "username", "nickname"], "manage friends; rename: a name only you see"),
    ("/block", ["username"], "block or unblock (blank to list)"),
    ("/history", ["on|off"], "on (1): keep messages and scroll back; off (0): they fade"),
    ("/messages", ["on|off"], "off (0): stay online, but receive nothing new · /m"),
    ("/help", ["command"], "the help page, or one command on it"),
    ("/settings", [], "open settings"),
    ("/key", ["username"], "key code to compare in person"),
    ("/trust", ["username*"], "trust someone's new key"),
    ("/quit", [], "quit Psst (⌘Q)"),
]

/// /status: what each number means. 1 mutes pings and mention sounds; 2 hides you from the online list.
let statusNames = ["online", "do not disturb", "invisible"]

func statusArg(_ s: String) -> Int? {
    let w = s.lowercased().trimmingCharacters(in: .whitespaces)
    return Int(w).flatMap { statusNames.indices.contains($0) ? $0 : nil } ?? statusNames.firstIndex(of: w) ?? (w == "dnd" ? 1 : nil)
}

/// Short forms, expanded once a space follows: /r = /room, /r c = /room create, /i = /invite, /a = /accept, /j = /join,
/// /rq = /request.
let shortForms = ["/r": "/room", "/i": "/invite", "/a": "/accept", "/j": "/join", "/rq": "/request", "/m": "/messages"]

/// on/off, or 1/0; nil for anything else.
func onOff(_ s: String) -> Bool? { ["on": true, "1": true, "off": false, "0": false][s.lowercased()] }

func expand(_ text: String) -> String {
    var out = text
    if let space = out.firstIndex(of: " "), let long = shortForms[out[..<space].lowercased()] { out = long + out[space...] }
    if out.lowercased().hasPrefix("/room c ") { out = "/room create " + out.dropFirst(8) }
    return out
}

/// While typing a room description (/room create … or /room … set desc …), wraps it in quotes so its spaces aren't
/// read as more parameters. The new text and where the cursor goes (inside the closing quote), or nil when nothing changes.
func quoteDesc(_ text: String) -> (text: String, cursor: Int)? {
    let w = text.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
    guard w.count > 2, w[0].lowercased() == "/room" else { return nil }
    var at: Int  // the description's first word
    if w[1].lowercased() == "create" {
        guard w.count > 3 else { return nil }  // still on the room name
        at = typeNames.indices.contains(Int(w[3]) ?? -1) ? 4 : 3  // after the type, if one was given
    } else if let s = w.firstIndex(where: { $0.lowercased() == "set" }), s <= 2, w.count > s + 2, w[s + 1].lowercased() == "desc" {
        at = s + 2
    } else { return nil }
    guard w.count > at else { return nil }
    let desc = w[at...].joined(separator: " ")
    guard let f = desc.first, !"\"“".contains(f) else { return nil }
    let new = w[..<at].joined(separator: " ") + " \"" + desc + "\""
    return (new, (new as NSString).length - 1)
}

/// Markdown markers pair up while typing a message: *, ` and ~ bring their closer, typing a closer steps over it, and a
/// second * or ~ in an empty pair doubles it (**bold**, ~~strike~~). Only at a word's edge, so 2*3 stays as typed.
/// What to insert at the cursor (which then moves one right): "" steps over; nil types the key as usual.
func autoPair(_ text: String, at i: Int, typed: String) -> String? {
    let s = text as NSString
    guard ["*", "`", "~"].contains(typed), !text.hasPrefix("/"), i <= s.length else { return nil }
    func char(_ j: Int) -> String { j >= 0 && j < s.length ? s.substring(with: NSRange(location: j, length: 1)) : " " }  // edges count as space
    func blank(_ j: Int) -> Bool { char(j).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    var l = 0, r = 0
    while char(i - 1 - l) == typed { l += 1 }
    while char(i + r) == typed { r += 1 }
    if l > 0, l == r, blank(i - 1 - l), typed != "`" { return typed + typed }  // *|* → **|**
    if r > 0 { return "" }
    return l == 0 && blank(i - 1) && blank(i) ? typed + typed : nil
}

/// Backspace inside an empty pair (*|*) takes out both.
func emptyPair(_ text: String, at i: Int) -> Bool {
    let s = text as NSString
    guard i > 0, i < s.length, !text.hasPrefix("/") else { return false }
    let a = s.substring(with: NSRange(location: i - 1, length: 1))
    return ["*", "`", "~"].contains(a) && a == s.substring(with: NSRange(location: i, length: 1))
}

/// The chat bar's field editor: pairs markdown markers as they're typed (see autoPair).
final class PairingEditor: NSTextView {
    override func insertText(_ string: Any, replacementRange: NSRange) {
        let typed = (string as? String) ?? (string as? NSAttributedString)?.string ?? "", at = selectedRange()
        guard replacementRange.location == NSNotFound, at.length == 0, let add = autoPair(self.string, at: at.location, typed: typed) else {
            return super.insertText(string, replacementRange: replacementRange)
        }
        if !add.isEmpty { super.insertText(add, replacementRange: replacementRange) }
        setSelectedRange(NSRange(location: at.location + 1, length: 0))  // between the pair, or past the closer
    }
}

/// "/friend [list|add|remove]* [username]": one placeholder per parameter, written like the README; * = required.
/// /help [command]: the command's full name, short forms too (r → /room); nil when there's no such command.
func commandName(_ name: String) -> String? {
    let n = "/" + name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/ "))
    return commands.first { $0.name == (shortForms[n] ?? n) }?.name
}

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
    let createLabel = "/room create [room name]* [type] [desc]", setLabel = "/room [room name] set [name|desc|password|type]* [new]*"
    if w.count == 1 {  // an option, or the room to change
        guard !first.isEmpty, !["create", "set", "member"].contains(where: { $0.hasPrefix(first) }) else {
            return c.room == "public" ? ("/room [create|member]*", "[create|member]", "make a room, or see who's in #public")
                : ("/room [create|set|member]*", "[create|set|member]", "make a room, change \(here) (or a room you name first), or manage its members")
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
        let type = Int(w[2]).flatMap { typeNames.indices.contains($0) ? $0 : nil }
        if w.count == 3, type != nil || w[2].isEmpty {
            return (createLabel, "[type]", type.map { "\($0): \(typeNames[$0])" + ($0 == 1 || $0 == 2 ? " · you'll set the password next" : "") }
                    ?? "optional: who can get in (default 0), then a description")
        }
        return (createLabel, "[desc]", "optional: what \(r) is about, for /browse" + (type == nil ? " · type 0, invite only" : ""))
    }
    if first == "member" {  // [list|kick|ban] [username], in the room you're in
        let label = "/room member [list|kick|ban]* [username]*", act = w[1].lowercased()
        let boss = c.room != "public" && !c.owner.isEmpty && c.owner == c.me
        if w.count == 2 {
            return (label, "[list|kick|ban]", boss ? "list who's in \(here), or kick or ban someone"
                    : "list who's in \(here)" + (c.owner.isEmpty || c.room == "public" ? "" : " · \(c.owner) made it and can kick or ban"))
        }
        switch act {
        case "list": return (label, "", "who's in \(here)")
        case "kick", "ban":
            guard c.room != "public" else { return (label, "[list|kick|ban]", "#public has no kick or ban") }
            guard boss else { return (label, "[username]", "only \(here)'s creator can \(act)") }
            let n = clean(w[2])
            if act == "ban", c.bans.contains(n) { return (label, "[username]", "lifts \(n)'s ban on \(here)") }
            let out = act == "kick" ? "" : " and keeps them out"
            return (label, "[username]", n.isEmpty ? "who to remove from \(here)" + out : "removes \(n) from \(here)" + out)
        default: return (label, "[list|kick|ban]", "list, kick or ban")
        }
    }
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
struct Suggestion { var label: String, detail = "", replace: String, dot: Bool? = nil, run = false, sub: [Suggestion]? = nil, busy = false }  // busy: red dot

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
    var owner = "", bans: [String] = []                    // this room's creator (who can kick and ban) and who is banned
    var status = 0, busy: [String] = []                    // mine (see statusNames), and who is in do not disturb
    var aliases: [String: String] = [:]                    // friend -> the nickname I gave them
}

/// What you can do to someone, after picking them from a list.
func actions(_ n: String, _ c: Ctx) -> [Suggestion] {
    guard n != c.me else { return [Suggestion(label: "show my key code", replace: "/key", run: true)] }
    guard c.roster.contains(n) || c.friends.contains(n) || c.members.contains(n) else { return [] }
    var a = [c.friends.contains(n) ? Suggestion(label: "remove friend", replace: "/friend remove \(n)", run: true)
                                   : Suggestion(label: "add friend", replace: "/friend add \(n)", run: true)]
    if c.friends.contains(n) { a.append(Suggestion(label: c.aliases[n] == nil ? "give a nickname" : "change nickname", replace: "/friend rename \(n) ")) }
    if c.room != "public", c.roster.contains(n), !c.members.contains(n) {
        a.append(Suggestion(label: "invite to #\(c.room)", replace: "/invite \(n)", run: true))
    }
    if c.room != "public", !c.owner.isEmpty, c.owner == c.me, c.members.contains(n) {
        a.append(Suggestion(label: "kick from #\(c.room)", replace: "/room member kick \(n)", run: true))
        a.append(Suggestion(label: "ban from #\(c.room)", replace: "/room member ban \(n)", run: true))
    }
    if c.roster.contains(n) { a.append(Suggestion(label: "ping", replace: "/ping \(n)", run: true)) }
    a.append(Suggestion(label: c.blocked.contains(n) ? "unblock" : "block", replace: "/block \(n)", run: true))
    a.append(Suggestion(label: "compare key code", replace: "/key \(n)", run: true))
    return a
}

/// Commands that, sent bare, open their list as a menu to pick from. The value is the typed text that lists it.
func listMenu(_ s: String) -> String? {
    let c = s.lowercased().split(separator: " ").joined(separator: " ")
    let lists = ["/online", "/status", "/ping", "/room", "/browse", "/join", "/request", "/invite", "/block", "/friend list", "/friend add", "/friend remove",
                 "/room member list", "/room member kick", "/room member ban"]
    return c == "/friend" ? "/friend list " : c == "/room member" ? "/room member list " : lists.contains(c) ? c + " " : nil
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
                Suggestion(label: ((c.aliases[n] ?? (inRoom ? c.nicks[n] : nil)).map { "\($0) · " } ?? "") + n + (c.room != "public" && n == c.owner ? " ◆" : ""),
                           detail: ([n == c.me ? "you" : tag && c.friends.contains(n) ? "friend" : ""] + (c.busy.contains(n) ? ["do not disturb"] : []))
                               .filter { !$0.isEmpty }.joined(separator: " · "),
                           replace: base, dot: inRoom || c.roster.contains(n), sub: actions(n, c), busy: c.busy.contains(n))  // replace: the list it's in
            }
        }
        let others = c.roster.filter { $0 != c.me }
        switch (cmd.name, words.count) {
        case ("/status", 1):
            return statusNames.indices.map { Suggestion(label: "\($0)", detail: statusNames[$0] + ($0 == c.status ? " · now" : ""), replace: base + "\($0)", run: true) }
                .filter { fits($0.label) }
        case ("/online", 1): return people(c.roster.filter(c.friends.contains) + c.roster.filter { !c.friends.contains($0) })
        case ("/room", 1):  // an option, a room you're in to change, then the other rooms on the network, as in /browse
            var options = [("create", "make a room")]
            if c.room != "public" {  // in public: nothing to edit offered
                options += [("set", "change #\(c.room)")] + c.joined.filter { $0 != "public" && $0 != c.room }.map { ($0, "change #\($0)") }
            }
            let listed = Set(options.map(\.0) + [c.room])
            return options.filter { fits($0.0) }.map { Suggestion(label: $0.0, detail: $0.1, replace: base + $0.0 + ($0.0 == "create" || $0.0 == "set" ? " " : " set ")) }
                + (fits("member") ? [Suggestion(label: "member", detail: c.room != "public" && c.owner == c.me ? "list, kick or ban people in #\(c.room)" : "who's in #\(c.room)",
                                                replace: base + "member ")] : [])
                + suggest("/browse " + token, c).filter { !listed.contains(String($0.label.dropFirst())) }
        case ("/room", 3) where words[0].lowercased() == "create":  // the type: Enter makes the room, Tab goes on to a description
            return typeNames.indices.filter { fits(String($0)) }
                .map { Suggestion(label: "\($0)", detail: typeNames[$0] + ($0 == 0 ? " · default" : ""), replace: base + "\($0)", run: true) }
        case ("/room", 2) where words[0].lowercased() == "member":  // kick and ban: only for the room's creator
            return plain(["list"] + (c.room != "public" && !c.owner.isEmpty && c.owner == c.me ? ["kick ", "ban "] : []))
        case ("/room", 3) where words[0].lowercased() == "member":
            switch words[1].lowercased() {
            case "list": return people(c.members, inRoom: true)
            case "kick": return plain(c.members.filter { $0 != c.me })
            case "ban": return plain(c.members.filter { $0 != c.me && !c.bans.contains($0) })
                + c.bans.filter(fits).map { Suggestion(label: $0, detail: "banned · lift", replace: base + $0, run: true) }
            default: return []
            }
        case ("/room", _) where words[0].lowercased() != "create" && words[0].lowercased() != "member":  // [room name] set [name|desc|password|type] [new]
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
        case ("/ping", 1): return plain(others)
        case ("/trust", 1): return plain(c.changed)
        case ("/history", 1), ("/messages", 1): return plain(["on", "off"])
        case ("/help", 1):  // every command with its format; picking one opens the help page there
            return commands.filter { fits(String($0.name.dropFirst())) || fits($0.name) }
                .map { Suggestion(label: usage($0), detail: $0.help, replace: "/help " + $0.name.dropFirst(), run: true) }
        case ("/leave", 1): return plain(["silent"])
        case ("/friend", 1): return plain(["list ", "add ", "remove ", "rename "])
        case ("/friend", 2) where words[0] == "rename":  // then type the nickname
            return c.friends.filter(fits).map { Suggestion(label: $0, detail: c.aliases[$0] ?? "", replace: base + $0 + " ") }
        case ("/friend", 2) where words[0] == "list":
            return people(c.friends.filter(c.roster.contains) + c.friends.filter { !c.roster.contains($0) }, tag: false)
        case ("/friend", 2) where words[0] == "add": return plain(others.filter { !c.friends.contains($0) })
        case ("/friend", 2) where words[0] == "remove": return plain(c.friends)
        default: return []
        }
    }
    if let r = text.range(of: #"(?<!\S)@[\p{L}\p{N}_#-]*$"#, options: .regularExpression) {  // "@an" or "@ana#04": who to mention
        let q = text[r].dropFirst().lowercased(), mine = [c.me, c.nicks[c.me] ?? c.me]
        var seen = Set<String>()
        let names = (c.roster + c.members + c.nicks.values).filter { !mine.contains($0) && $0.lowercased().hasPrefix(q) && seen.insert($0).inserted }
        return names.sorted { ($0.lowercased() == q ? 0 : 1, $0.lowercased()) < ($1.lowercased() == q ? 0 : 1, $1.lowercased()) }.prefix(6)  // exact first: Enter sends
            .map { Suggestion(label: "@" + $0, replace: String(text[..<r.lowerBound]) + "@" + $0) }
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
