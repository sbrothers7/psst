import AppKit
import Carbon.HIToolbox
import CryptoKit
import Network

// MARK: - Self-test (host routing + one real TCP round trip)

func check(_ ok: Bool, _ what: String) { if !ok { print("FAIL:", what); exit(1) } }

func selftest() {
    let s = Server(retention: 60)
    var inbox: [Int: [Msg]] = [:]
    for id in 1...3 { s.add(id, send: { inbox[id, default: []].append($0) }, close: {}) }
    func last(_ id: Int) -> Msg? { inbox[id]?.last }
    func saw(_ id: Int, _ text: String) -> Bool { inbox[id]?.contains { $0.text == text } ?? false }
    func lastNote(_ id: Int) -> String? { inbox[id]?.last { $0.t == "note" }?.text }

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
    check(lastNote(1) == "ana2 was invited to #math", "inviter told who was invited where")
    s.handle(2, Msg(t: "join", room: "math"))
    check(s.clients[2]?.rooms.contains("math") == true, "invited user can join")
    check(lastNote(1) == "ana2 has joined #math", "the room hears who joined")
    s.handle(1, Msg(t: "invite", room: "math", text: "ghost"))
    check(last(1)?.text == "no one named ghost" && last(4)?.t != "invite", "invisible users can't be found to invite")

    func sawCT(_ id: Int, _ ct: String) -> Bool { inbox[id]?.contains { $0.ct == ct } ?? false }
    s.handle(1, Msg(t: "say", room: "math", ct: "CT", wraps: ["ana2": "W"]))
    check(sawCT(2, "CT") && !sawCT(3, "CT"), "room messages stay in room")
    s.handle(1, Msg(t: "say", room: "math", text: "plain"))
    check(!saw(2, "plain") && !s.history.contains { $0.text == "plain" }, "host drops plain text in private rooms")
    s.handle(3, Msg(t: "say", room: "math", ct: "X", wraps: [:]))
    check(!sawCT(1, "X"), "non-members can't post to room")
    func typing(_ id: Int) -> Msg? { inbox[id]?.last { $0.t == "typing" } }
    inbox = [:]
    s.handle(2, Msg(t: "typing", room: "math"))
    check(typing(1)?.from == "ana2" && typing(1)?.room == "math" && typing(2) == nil && typing(3) == nil, "typing reaches the rest of the room only")
    s.handle(4, Msg(t: "typing", room: "public"))
    check(typing(1)?.from == "ana2" && !s.history.contains { $0.t == "typing" }, "invisible people don't show typing in public; typing isn't kept")

    inbox = [:]
    s.handle(3, Msg(t: "ping", text: "ana"))
    check(last(1)?.t == "ping" && last(1)?.from == "bob" && last(1)?.room == nil && lastNote(3) == "pinged ana", "ping reaches them")
    s.handle(3, Msg(t: "ping", text: "ana2"))
    check(inbox[2]?.contains { $0.t == "ping" } != true && lastNote(3)?.hasPrefix("you can ping again in") == true, "one ping per 30 s")
    s.handle(2, Msg(t: "ping", room: "math", text: "ana"))
    check(last(1)?.t == "ping" && last(1)?.from == "ana2" && last(1)?.room == "math", "a ping from a room says which")
    s.handle(1, Msg(t: "ping", text: "ghost"))
    s.handle(2, Msg(t: "ping", text: "ana2"))
    check(inbox[4]?.contains { $0.t == "ping" } != true && lastNote(1) == "no one named ghost" && inbox[2]?.contains { $0.t == "ping" } != true,
          "no pinging invisible people or yourself")
    check(mentions("hey @ana!", ["ana"]) && mentions("@Ana hi", ["ana"]) && mentions("yo @Z", ["ana", "z"]) && !mentions("hey @ana2", ["ana"])
          && !mentions("x@ana", ["ana"]) && !mentions("hey ana", ["ana"]) && !mentions("@ana", []), "mentions")
    check(expand("/r c math") == "/room create math" && expand("/R ") == "/room " && expand("/i ana") == "/invite ana" && expand("/a all") == "/accept all"
          && expand("/j art pw") == "/join art pw" && expand("/room c x") == "/room create x" && expand("/r") == "/r" && expand("/rooms x") == "/rooms x"
          && expand("hi /r x") == "hi /r x" && expand("/rq art") == "/request art" && expand("/m 0") == "/messages 0", "short commands")
    check(onOff("ON") == true && onOff("1") == true && onOff("off") == false && onOff("0") == false && onOff("2") == nil, "on/off also as 1/0")

    inbox = [:]
    s.handle(3, Msg(t: "nick", from: "bob", dnd: true))
    check(inbox[1]?.last { $0.t == "who" }?.busy == ["bob"], "everyone sees who is in do not disturb")
    s.handle(1, Msg(t: "ping", text: "bob"))
    check(lastNote(1) == "bob is in do not disturb" && inbox[3]?.contains { $0.t == "ping" } != true, "no pings in do not disturb")
    s.handle(2, Msg(t: "nick", from: "ana2", noPings: true))
    s.handle(1, Msg(t: "ping", text: "ana2"))
    check(lastNote(1) == "ana2 turned pings off" && inbox[2]?.contains { $0.t == "ping" } != true, "pings can be turned off")
    s.handle(3, Msg(t: "nick", from: "bob"))
    s.handle(2, Msg(t: "nick", from: "ana2"))
    check(s.clients[3]?.name == "bob" && s.clients[3]?.dnd == false && s.clients[2]?.noPings == false, "back to normal")
    check(friendAlias("  Best   Friend!! ") == "Best Friend" && friendAlias("   ") == "" && friendAlias(String(repeating: "x", count: 30)).count == 20,
          "friend nicknames: tidy, short")
    let pals = Ctx(me: "me", roster: ["ana", "me"], friends: ["ana", "bo"], aliases: ["ana": "Bestie"])
    check(suggest("/friend rename ", pals).map { "\($0.label)|\($0.detail)|\($0.replace)|\($0.run)" } == ["ana|Bestie|/friend rename ana |false", "bo||/friend rename bo |false"],
          "rename lists friends, then waits for the nickname")
    check(suggest("/online ", pals).first?.label == "Bestie · ana", "lists show my nickname for a friend")
    check(actions("ana", pals).contains { $0.replace == "/friend rename ana " && !$0.run } && !actions("zed", Ctx(roster: ["zed"])).contains { $0.replace.hasPrefix("/friend rename") },
          "friends get a nickname action")
    check(statusArg("1") == 1 && statusArg("DND") == 1 && statusArg("invisible") == 2 && statusArg("online") == 0 && statusArg("7") == nil, "status words and numbers")

    let e = emojify(":fire: :+1: :Grinning: :heart: :greek_small_letter_pi: 10:30:45 :nope: a:b")
    check(e == "🔥 👍 😀 ❤️ π 10:30:45 :nope: a:b", "emojify: \(e)")

    func hint(_ t: String, _ roster: [String] = [], _ rooms: [String] = []) -> [Suggestion] { suggest(t, Ctx(roster: roster, joined: rooms)) }
    check(hint("/").count == commands.count, "/ lists every command")
    let tagA = "0412", tagB = "7731"
    let tagged = "ana#0412 has joined #1234 · bo#77777 · #chess"
    check(tagPattern.matches(in: tagged, range: NSRange(location: 0, length: (tagged as NSString).length)).map { (tagged as NSString).substring(with: $0.range) } == ["#0412"],
          "only a name's #tag is greyed, not rooms")
    check(validTag(newTag()) != nil && validTag("0412") == "0412" && validTag("412") == nil && validTag("04a2") == nil && validTag("٠١٢٣") == nil && validTag(nil) == nil,
          "tags: 4 digits, picked on this Mac")
    check(cleanHandle(" ana#04x12 ") == "ana#0412" && cleanHandle("bo b!") == "bob" && cleanHandle("ana#") == "ana" && splitTag("ana#0412") == ("ana", "0412")
          && splitTag("ana").tag == nil, "name#tag as typed")
    let twins = ["ana#0412", "ana#7731", "bo#0001"]
    check(whoIs("bo", among: twins) == ["bo#0001"] && whoIs("ana", among: twins) == ["ana#0412", "ana#7731"] && whoIs("ANA#7731", among: twins) == ["ana#7731"]
          && whoIs("zed", among: twins) == ["zed"] && whoIs("ana#0412", among: twins + ["ana#0412"]) == ["ana#0412"], "a name finds the one person, or everyone sharing it")
    check(mentions("hi @ana", ["ana#0412"]) && mentions("hi @ana#0412!", ["ana#0412"]) && !mentions("hi @ana#7731", ["ana#0412"]) && !mentions("hi @anaa", ["ana#0412"]),
          "@name mentions every ana, @name#tag just one")
    check(suggest("hi @an", Ctx(me: "me#0001", roster: ["ana#0412", "me#0001"])).map(\.replace) == ["hi @ana#0412"] && suggest("@ana#7", Ctx(roster: ["ana#0412", "ana#7731"])).map(\.replace) == ["@ana#7731"],
          "@ completes name#tag")
    let tg = Server(retention: 3600)
    var tgIn: [Int: [Msg]] = [:]
    for id in 1...3 { tg.add(id, send: { tgIn[id, default: []].append($0) }, close: {}) }
    tg.handle(1, Msg(t: "hello", from: "ana", tag: tagA))
    tg.handle(2, Msg(t: "hello", from: "ana", tag: tagB))
    tg.handle(3, Msg(t: "hello", from: "bo"))
    check(tgIn[1]?.first { $0.t == "you" }?.from == "ana#\(tagA)" && tgIn[2]?.first { $0.t == "you" }?.from == "ana#\(tagB)" && tgIn[3]?.first { $0.t == "you" }?.from == "bo",
          "the host shows each Mac's own tag; an older Psst sends none")
    tg.handle(3, Msg(t: "ping", text: "ana"))
    check(tgIn[3]?.last { $0.t == "note" }?.text?.hasPrefix("which one? ") == true && tgIn[1]?.contains { $0.t == "ping" } != true, "a shared name asks which one")
    tg.handle(3, Msg(t: "ping", text: "ana#\(tagB)"))
    check(tgIn[2]?.contains { $0.t == "ping" } == true && tgIn[1]?.contains { $0.t == "ping" } != true, "name#tag reaches the one")
    tg.handle(1, Msg(t: "ping", text: "ana"))
    check(tgIn[2]?.filter { $0.t == "ping" }.count == 2 && tgIn[1]?.last { $0.t == "note" }?.text == "pinged ana#\(tagB)", "ana pinging ana means the other one")
    check(commandName("room") == "/room" && commandName("/R") == "/room" && commandName("m") == "/messages" && commandName("nope") == nil,
          "/help [command] opens the help page at that command, short forms too")
    check(Set(helpGroups.flatMap(\.names)) == Set(commands.map(\.name)) && helpGroups.flatMap(\.names).count == commands.count
          && commands.allSatisfy { commandDetails[$0.name] != nil } && commandDetails.count == commands.count, "the help page explains every command once")
    check(listMenu("/help") == nil && suggest("/help ", Ctx()).count == commands.count
          && suggest("/help me", Ctx()).map { "\($0.label)|\($0.replace)|\($0.run)" } == ["/messages [on|off]|/help messages|true"], "/help lists commands; picking one explains it")
    check(usage(commands[0]) == "/online [username]", "parameters in square brackets")
    check(hint("/inv").first?.replace == "/invite ", "command completes with room for its argument")
    check(hint("/invite a", ["ana", "bob"]).map(\.replace) == ["/invite ana"], "/invite suggests people")
    check(hint("/join m", [], ["math", "public"]).map(\.replace) == ["/join math"], "/join suggests rooms")
    check(hint("/room create ma").isEmpty, "free argument has nothing to pick")
    check(paramGuide("/room create ma")?.label == "/room create [room name]* [type] [desc]" && paramGuide("/room create ma")?.focus == "[room name]", "guide shows format")
    check(usage(commands.first { $0.name == "/trust" }!) == "/trust [username]*" && paramGuide("/friend ")?.label == "/friend [list|add|remove|rename]* [username] [nickname]",
          "a star marks required parameters")
    let rc = Ctx(room: "art", joined: ["public", "art", "club"], open: ["art": 1, "club": 2], types: ["club": 2])
    let g = { (t: String) in paramGuide(t, rc).map { "\($0.label) | \($0.focus) | \($0.help)" } ?? "nil" }
    check(g("/room ") == "/room [create|set|member]* | [create|set|member] | make a room, change #art (or a room you name first), or manage its members"
          && suggest("/room ", rc).map(\.replace) == ["/room create ", "/room set ", "/room club set ", "/room member "]
          && suggest("/room cl", rc).map(\.replace) == ["/room club set "] && hint("/room ").map(\.label) == ["create", "member"],
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
    let cl = "/room create [room name]* [type] [desc]"
    check(g("/room create club") == "\(cl) | [room name] | #club already exists: /join it instead"
          && g("/room create current") == "\(cl) | [room name] | #current can't be a room name"
          && g("/room create chess ") == "\(cl) | [type] | optional: who can get in (default 0), then a description"
          && g("/room create chess 1") == "\(cl) | [type] | 1: password only · you'll set the password next"
          && g("/room create chess 1 after") == "\(cl) | [desc] | optional: what #chess is about, for /browse"
          && g("/room create chess after") == "\(cl) | [desc] | optional: what #chess is about, for /browse · type 0, invite only",
          "create guide: \(g("/room create chess after"))")
    check(suggest("/room create chess ", rc).map(\.replace) == ["/room create chess 0", "/room create chess 1", "/room create chess 2", "/room create chess 3"]
          && suggest("/room create chess ", rc).allSatisfy(\.run) && hint("/room create chess af").isEmpty, "create: pick a type, or type a description")
    let inPublic = Ctx(joined: ["public", "club"], open: ["club": 2, "art": 1])
    check(suggest("/room ", inPublic).map(\.label) == ["create", "member", "#art", "#club"] && suggest("/room ", inPublic).suffix(2).map(\.replace) == ["/request art", "/join club"]
          && suggest("/room a", inPublic).map(\.label) == ["#art"], "rooms on the network follow the options")
    check(suggest("/room ", Ctx(joined: ["public", "club"])).map(\.label) == ["create", "member"]
          && paramGuide("/room ", Ctx(joined: ["public", "club"]))?.label == "/room [create|member]*", "in public: no editing offered")
    check(paramGuide("/room set name x", Ctx(joined: ["public"]))?.help == "#public can't be changed: name a room you're in", "no changing #public")
    check(createArgs("chess 2 on weekends") == ("chess", "on weekends", 2) && createArgs("Chess") == ("chess", "", 0)
          && createArgs("chess \"3 people\"") == ("chess", "3 people", 0) && createArgs("chess 3") == ("chess", "", 3)
          && createArgs("chess 9 lives") == ("chess", "9 lives", 0) && createArgs("chess on weekends 2") == ("chess", "on weekends 2", 0),
          "create: a second word 0–3 is the type")
    let ed = { (a: String) in roomEdit(a, current: "art").map { "\($0.room)|\($0.field)|\($0.value)" } ?? "nil" }
    check(ed("set name lounge") == "art|name|lounge" && ed("club set desc on weekends") == "club|desc|on weekends"
          && ed("Current set TYPE 2") == "art|type|2" && ed("club lounge") == "nil" && ed("set") == "art||", "set: room name optional, current is this room")
    let own = Ctx(me: "me", room: "club", roster: ["me", "zoe", "al"], joined: ["public", "club"], members: ["me", "zoe"], owner: "me", bans: ["al"])
    let zoes = Ctx(me: "me", room: "club", roster: ["me", "zoe"], members: ["me", "zoe"], owner: "zoe")
    check(suggest("/online ", zoes).map(\.label) == ["me", "zoe ◆"] && suggest("/online ", Ctx(me: "me", roster: ["me", "zoe"], owner: "zoe")).map(\.label) == ["me", "zoe"],
          "◆ marks the room's creator, inside that room")
    check(suggest("/room member ", own).map(\.replace) == ["/room member list", "/room member kick ", "/room member ban "]
          && suggest("/room member ", rc).map(\.replace) == ["/room member list"], "member: kick and ban only for the creator")
    check(suggest("/room member kick ", own).map(\.replace) == ["/room member kick zoe"]
          && suggest("/room member ban ", own).map { "\($0.label)|\($0.detail)" } == ["zoe|", "al|banned · lift"], "kick: members; ban: members, then who's banned")
    check(paramGuide("/room member kick zoe", own)?.help == "removes zoe from #club" && paramGuide("/room member ban al", own)?.help == "lifts al's ban on #club"
          && paramGuide("/room member kick zoe", rc)?.help == "only #art's creator can kick", "member guide")
    check(actions("zoe", own).map(\.replace) == ["/friend add zoe", "/room member kick zoe", "/room member ban zoe", "/ping zoe", "/block zoe", "/key zoe"],
          "the creator can kick or ban from someone's menu")
    let qd = { (t: String) in quoteDesc(t).map { "\($0.text)|\($0.cursor)" } ?? "nil" }
    check(qd("/room create chess a") == "/room create chess \"a\"|21" && qd("/room create chess 2 a") == "/room create chess 2 \"a\"|23"
          && qd("/room create chess 2") == "nil" && qd("/room create chess 3d") == "/room create chess \"3d\"|22" && qd("/room create chess \"a\"") == "nil"
          && qd("/room club set desc a b") == "/room club set desc \"a b\"|24" && qd("/room set desc ") == "nil" && qd("/room create ch") == "nil",
          "descriptions get quotes as they're typed: \(qd("/room create chess a"))")
    check(autoPair("", at: 0, typed: "*") == "**" && autoPair("hi ", at: 3, typed: "`") == "``" && autoPair("2", at: 1, typed: "*") == nil
          && autoPair("**", at: 1, typed: "*") == "**" && autoPair("**b**", at: 3, typed: "*") == "" && autoPair("**b*", at: 4, typed: "*") == nil
          && autoPair("~~s~~", at: 4, typed: "~") == "" && autoPair("``", at: 1, typed: "`") == "" && autoPair("/room ", at: 6, typed: "*") == nil
          && autoPair("word", at: 4, typed: "*") == nil && autoPair("a", at: 0, typed: "*") == nil && autoPair("", at: 0, typed: "a") == nil,
          "markdown markers pair up at word edges")
    check(emptyPair("**", at: 1) && emptyPair("a ``", at: 3) && !emptyPair("*a*", at: 2) && !emptyPair("*", at: 1) && !emptyPair("/x **", at: 4), "backspace empties a pair")
    check(suggest("#q?", Ctx(asks: ["#q?": [Suggestion(label: "1", replace: "x", run: true)]])).map(\.replace) == ["x"], "a question's answers")
    check(unquote(" \"chess club\" ") == "chess club" && unquote("“quiet”") == "quiet" && unquote("plain words") == "plain words", "quotes optional")
    check(paramGuide("/friend a")?.focus == "[list|add|remove|rename]", "guide highlights first parameter")
    check(paramGuide("/friend add b")?.focus == "[username]", "guide moves to second parameter")
    check(paramGuide("/quit ") == nil && paramGuide("/fri") == nil && paramGuide("hi") == nil, "no guide without parameters")
    check(hint("hi :fir").first?.replace == "hi 🔥", "emoji suggestions: \(hint("hi :fir").map(\.label))")
    check(hint("at 10:30").isEmpty && hint("a :x").isEmpty, "no emoji guide for times or 1 letter")
    check(hint("/friend ").map(\.replace) == ["/friend list ", "/friend add ", "/friend remove ", "/friend rename "], "/friend shows subcommands")
    check(suggest("/friend add b", Ctx(roster: ["bo", "bea"], friends: ["bo"])).map(\.replace) == ["/friend add bea"],
          "/friend add suggests people not yet friends")
    check(suggest("/friend remove ", Ctx(friends: ["bo"])).map(\.replace) == ["/friend remove bo"], "/friend remove suggests friends")
    check(suggest("/block z", Ctx(roster: ["ana"], blocked: ["zed"])).map(\.replace) == ["/block zed"], "/block suggests blocked to unblock")

    // Pickable lists: name + dot, then what to do with them
    let cx = Ctx(me: "me", room: "club", roster: ["al", "bo", "me", "zoe"], friends: ["bo", "gone"], joined: ["public", "club"],
                 invited: ["band"], open: ["club": 2, "art": 3, "band": 1], members: ["me", "zoe"], nicks: ["zoe": "Z"], requests: ["al", "bo"])
    let online = suggest("/online ", cx)
    check(online.map(\.label) == ["bo", "al", "me", "zoe"] && online.allSatisfy { $0.dot == true }, "status: friends first, all online")
    check(online[0].detail == "friend" && online[2].detail == "you" && online.allSatisfy { $0.replace == "/online " && !$0.run },
          "status rows open a menu and leave the typed text alone")
    check(suggest("/status ", Ctx(status: 1)).map { "\($0.label) \($0.detail)" } == ["0 online", "1 do not disturb · now", "2 invisible"], "status options")
    check(suggest("/online ", Ctx(me: "me", roster: ["al", "me"], friends: ["al"], busy: ["al"])).map { "\($0.detail) \($0.busy)" } == ["friend · do not disturb true", "you false"],
          "do not disturb shows in the online list, with a red dot")
    let at = Ctx(me: "me", room: "club", roster: ["ana", "ana2", "al", "me", "bo"], members: ["me", "zoe"], nicks: ["zoe": "Z", "me": "M"])
    check(suggest("hi @a", at).map(\.replace) == ["hi @al", "hi @ana", "hi @ana2"], "@ completes names")
    check(suggest("hi @ana", at).map(\.label) == ["@ana", "@ana2"] && suggest("@z", at).map(\.label) == ["@Z", "@zoe"],
          "exact name first, so Enter sends; nicknames too")
    check(suggest("@m", at).isEmpty && suggest("mail x@a", at).isEmpty && suggest("hi @al there", at).isEmpty, "not me, not inside words, only while typing it")
    check(suggest("/friend list ", cx).map { "\($0.label) \($0.dot!)" } == ["bo true", "gone false"], "friend list marks who is offline")
    let acts = online[1].sub ?? []  // al
    check(acts.map(\.replace) == ["/friend add al", "/invite al", "/ping al", "/block al", "/key al"] && acts.allSatisfy(\.run), "picking someone shows actions")
    check(suggest("/friend list ", cx).first?.sub?.first?.replace == "/friend remove bo", "friend list: pick, then remove")
    check(suggest("/friend list bo ", cx).isEmpty && suggest("/online al ", cx).isEmpty, "actions never go in the typed text")
    check(!(suggest("/room member list ", cx).last?.sub ?? []).contains { $0.label.hasPrefix("invite") }, "no invite for people already here")
    check(suggest("/room member list ", cx).map(\.label) == ["me", "Z · zoe"] && listMenu("/room member") == "/room member list "
          && menuRows("/room member list ", ["Z · zoe"], cx).depth == 1, "member list: nicknames, then what to do")
    check(suggest("/browse ", cx).map(\.replace) == ["/request art", "/join band", "/join club"] && suggest("/browse ", cx).allSatisfy(\.run),
          "rooms: ask, or join when invited or already in")
    check(suggest("/accept ", cx).map(\.replace) == ["/accept bo", "/accept al", "/accept all"], "accept: latest first, then all")
    check(hint("/invite a", ["ana"]).allSatisfy(\.run) && suggest("/block ", cx).allSatisfy(\.run) && hint("/friend ").allSatisfy(\.run)
          && hint("/fri").allSatisfy(\.run), "Enter runs what's picked, like sending a message")
    check(listMenu("/friend") == "/friend list " && listMenu("/Friend  add") == "/friend add " && listMenu("/browse") == "/browse "
          && listMenu("/accept") == nil && listMenu("/room lab") == nil && listMenu("hi") == nil, "bare list commands open menus")
    let fm = menuRows("/friend list ", ["bo"], cx)
    check(fm.depth == 1 && fm.title?.label == "bo" && fm.rows.first?.replace == "/friend remove bo", "menu opens the picked row")
    check(menuRows("/friend list ", ["al"], cx).depth == 0 && menuRows("/online ", ["al", "x"], cx).depth == 1, "a row that's gone backs the menu up")
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
    check(!validName("BigDick") && !validName("dick_69") && !validName("fuckboy") && !validName("sh1t")
          && validName("Dickson") && validName("Ishita") && validName("Cassandra") && validName("Hancock"), "no swearing in names")
    pv.handle(2, Msg(t: "nick", from: "BigDick"))
    check(pv.clients[2]?.name.hasPrefix("anon") == true, "host won't take a swear name from a modified Psst")
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
    ty.handle(3, Msg(t: "kick", room: "hall", text: "ana"))
    check(inT(1, "hall"), "only the creator kicks")
    ty.handle(1, Msg(t: "kick", room: "hall", text: "cy"))
    check(!inT(3, "hall") && tin[3]?.contains { $0.t == "left" && $0.room == "hall" } == true, "kick takes them out")
    ty.handle(3, Msg(t: "join", room: "hall"))
    check(inT(3, "hall"), "kicked, not banned: an open room lets them back")
    ty.handle(1, Msg(t: "ban", room: "hall", text: "cy"))
    ty.handle(3, Msg(t: "join", room: "hall"))
    let told = tin[1]?.last(where: { $0.t == "members" })
    check(!inT(3, "hall") && ty.bans["hall"] == ["cy"] && told?.names == ["cy"] && told?.from == "ana" && ty.snapshot().rooms["hall"]?.bans == ["cy"],
          "banned: kept out; members see the ban and the creator; the next host keeps it")
    ty.handle(1, Msg(t: "invite", room: "hall", text: "cy"))
    check(ty.invites["hall"]?.isEmpty != false, "can't invite someone banned")
    ty.handle(1, Msg(t: "ban", room: "hall", text: "cy"))
    ty.handle(3, Msg(t: "join", room: "hall"))
    check(inT(3, "hall") && ty.bans["hall"]?.isEmpty == true, "banning again lifts it")

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
    check(lastNote(1) == "ana2 has left #math", "the room hears who left")
    s.handle(1, Msg(t: "invite", room: "math", text: "ana2"))
    s.handle(2, Msg(t: "join", room: "math"))
    check(s.clients[2]?.rooms.contains("math") == true, "re-invited member rejoins")
    inbox[1] = []
    s.handle(2, Msg(t: "leave", room: "math", text: "silent"))
    check(s.clients[2]?.rooms.contains("math") == false && lastNote(1) == nil, "/leave silent leaves without a note")
    s.handle(1, Msg(t: "invite", room: "math", text: "ana2"))
    s.handle(2, Msg(t: "join", room: "math"))
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
    let direct = talk(testPort, [Msg(t: "hello", from: "net", addrs: ["10.4.4.4"]), Msg(t: "say", text: ping)]) { $0.contains { $0.text == ping } }
    check(direct.first?.from == "net", "tcp hello")
    check(!direct.contains { $0.addrs != nil }, "joining passes on no addresses")

    // Addresses: the next two in line's, never an invisible one's, once a minute (shareAddrs runs on a timer)
    var gotA: [Msg] = []
    let la = Line(NWConnection(to: .hostPort(host: "127.0.0.1", port: testPort), using: .tcp))
    let lb = Line(NWConnection(to: .hostPort(host: "127.0.0.1", port: testPort), using: .tcp))
    la.onMsg = { gotA.append($0) }
    la.start(); lb.start()
    la.send(Msg(t: "hello", from: "sa", since: 1, addrs: ["10.1.2.3", "nope"]))
    lb.send(Msg(t: "hello", from: "sb", hidden: true, since: 2, addrs: ["10.9.9.9"]))
    RunLoop.main.run(until: Date() + 0.5)
    let t0 = Date().timeIntervalSince1970
    net.shareAddrs(now: t0)
    let held = net.shared
    net.shareAddrs(now: t0 + 59)
    let stillHeld = net.shared
    net.shareAddrs(now: t0 + 601)
    RunLoop.main.run(until: Date() + 0.3)
    la.close(); lb.close()
    let shared = gotA.last { $0.t == "addrs" }?.addrs ?? []
    check(!held.contains("10.1.2.3") && !stillHeld.contains("10.1.2.3"), "a new next in line's address waits a random 1–10 minutes")
    check(net.successors.count == 2 && shared.contains("10.1.2.3") && !shared.contains("10.9.9.9") && !shared.contains("nope") && !shared.contains("10.4.4.4"),
          "then the host passes on the next in line's addresses, not invisible people's or anyone else's")

    // The wire: a key, then sealed lines only the other end can open; plain JSON (an older Psst) gets nothing
    let rawKey = Curve25519.KeyAgreement.PrivateKey()
    var wire = Data()
    let sniff = try! NWListener(using: .tcp, on: 47833)
    sniff.newConnectionHandler = { c in
        c.start(queue: .main)
        c.send(content: Data(rawKey.publicKey.rawRepresentation.base64EncodedString().utf8) + [10], completion: .idempotent)
        func more() { c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { d, _, done, _ in wire.append(d ?? Data()); if !done { more() } } }
        more()
    }
    sniff.start(queue: .main)
    RunLoop.main.run(until: Date() + 0.3)
    let out = Line(NWConnection(to: .hostPort(host: "127.0.0.1", port: 47833), using: .tcp))
    out.start()
    out.send(Msg(t: "hello", from: "secretname"))
    RunLoop.main.run(until: Date() + 0.5)
    out.close(); sniff.cancel()
    let sent = wire.split(separator: 10).map { Data(base64Encoded: Data($0)) }
    let theirKey = sent.first.flatMap { $0.flatMap { try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: $0) } }
    let opened = sent.count == 2 ? theirKey.flatMap { lineKey(rawKey, $0) }.flatMap { k in
        sent[1].flatMap { try? ChaChaPoly.open(ChaChaPoly.SealedBox(combined: $0), using: k) }
    } : nil
    check(!String(decoding: wire, as: UTF8.self).contains("secretname") && opened.map { String(decoding: $0, as: UTF8.self).contains("secretname") } == true,
          "on the wire: a key, then sealed lines that only the other end opens")
    var plain = Data()
    let old = NWConnection(to: .hostPort(host: "127.0.0.1", port: testPort), using: .tcp)
    old.start(queue: .main)
    old.send(content: try! JSONEncoder().encode(Msg(t: "hello", from: "oldpsst")) + [10], completion: .idempotent)
    func more(_ c: NWConnection) { c.receive(minimumIncompleteLength: 1, maximumLength: 65536) { d, _, done, _ in plain.append(d ?? Data()); if !done { more(c) } } }
    more(old)
    RunLoop.main.run(until: Date() + 0.5)
    old.cancel()
    check(plain.split(separator: 10).count == 1 && !net.clients.values.contains { $0.name == "oldpsst" }, "an older Psst's plain JSON gets the host's key and nothing else")
    let asked = talk(testPort, [Msg(t: "ad")]) { !$0.isEmpty }
    check(asked.first?.ad.flatMap { hostAd($0) }?.id == net.id && net.clients.values.allSatisfy(\.ready),
          "asked directly, a host says what its Bonjour listing would, without becoming a client")
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
    let woke = Server(retention: 60)  // startHost after a wake: the old listener is still closing
    woke.start(port: testPort, advertise: false)
    RunLoop.main.run(until: Date() + 2)  // clients redial every 2 s
    check(talk(testPort, [Msg(t: "hello", from: "woke")]) { !$0.isEmpty }.first?.from == "woke", "host restarted on its own port answers")
    woke.stop()
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
    check(trayDotColor(connected: false, wifiOnly: true, update: true) == .systemRed && trayDotColor(connected: true, wifiOnly: true, update: true) == .systemYellow
          && trayDotColor(connected: true, wifiOnly: false, update: true) == .systemBlue && trayDotColor(connected: true, wifiOnly: false, update: false) == nil,
          "tray dot: red disconnected, then yellow Wi-Fi only, then blue update")
    check(onlyWiFi([["awdl0"], ["llw0", "awdl0"]]) && !onlyWiFi([["awdl0", "en0"], ["awdl0"]]) && !onlyWiFi([]),
          "other Macs found only over peer-to-peer Wi-Fi: the network keeps Macs apart; none found: can't tell")
    check(NWTXTRecord(["id": "x", "since": "12.5"])["since"].flatMap(Double.init) == 12.5, "host start time survives the TXT record")
    let school: [Net] = [(ipv4("172.16.14.21")!, ipv4("255.255.252.0")!)]
    check(onMyNetworks(["172.16.13.5", "172.16.14.21", "172.16.20.1", "10.0.0.2", "172.16.15.300", "x", "1.2.3"], school) == ["172.16.13.5"],
          "only other Macs on this Mac's own network are asked directly")
    check(dotted(ipv4("172.16.14.21")!) == "172.16.14.21" && !localNets().contains { $0.addr >> 24 == 127 }, "addresses round-trip; loopback isn't shared")
    check(hostAd(["v": wireVersion, "id": "x", "since": "5", "up": "h", "upsince": "1", "hops": "2"], addr: "172.16.13.5")
          == HostAd(id: "x", since: 5, up: "h", upSince: 1, hops: 2, addr: "172.16.13.5") && hostAd(["v": wireVersion, "since": "5"]) == nil,
          "host advert from a TXT record or a direct answer")
    check(hostAd(["id": "x", "since": "5"]) == nil, "an older Psst, which can't read encrypted lines, is left out of the election")
    let ka = Curve25519.KeyAgreement.PrivateKey(), kb = Curve25519.KeyAgreement.PrivateKey()
    func bytes(_ k: SymmetricKey?) -> Data? { k?.withUnsafeBytes { Data($0) } }
    check(bytes(lineKey(ka, kb.publicKey)) != nil && bytes(lineKey(ka, kb.publicKey)) == bytes(lineKey(kb, ka.publicKey))
          && bytes(lineKey(ka, kb.publicKey)) != bytes(lineKey(ka, Curve25519.KeyAgreement.PrivateKey().publicKey)),
          "both ends of a line derive the same key; anyone else a different one")
    check(tagVersion(URL(string: "https://github.com/sbrothers7/psst/releases/tag/v1.4.0")) == "1.4.0"
          && tagVersion(URL(string: "https://github.com/sbrothers7/psst/releases")) == nil && tagVersion(nil) == nil, "version from the latest release's tag")
    check(isNewer("1.10", than: "1.9") && isNewer("1.3.1", than: "1.3") && isNewer("1.4", than: "1.3.1") && isNewer("1.0\n", than: "0") && !isNewer("1.2", than: "1.2") && !isNewer("1.1", than: "1.2") && isNewer("1.1.2-1", than: "1.1.2") && isNewer("1.1.3", than: "1.1.2-1") && !isNewer("1.1.2", than: "1.1.2-1"),
          "version compare")
    check(updateText(nil, state: nil, current: "1.1") == ("Psst 1.1", false) && updateText("1.1", state: nil, current: "1.1") == ("Psst 1.1 is up to date", false)
          && updateText("1.2", state: nil, current: "1.1") == ("Update available: 1.2", true) && updateText("1.2", state: "Downloading…", current: "1.1") == ("Downloading…", false)
          && updateText("1.0", state: nil, current: "1.1") == ("Psst 1.1 is up to date", false), "update status line")
    check(censor("what the Fuck, motherfucker") == "what the ••••, ••••••••••••", "swearing hidden, any case, inside words")
    check(censor("sh1t fuuuck @ss bullshit dicks") == "•••• •••••• ••• •••••••• •••••", "look-alikes, repeats, endings")
    check(censor("Scunthorpe class assume Ishita cocktail title cumulative spice niggle retardant") ==
          "Scunthorpe class assume Ishita cocktail title cumulative spice niggle retardant", "innocent words left alone")
    check(censor("hi! 👍🏽 **bold**") == "hi! 👍🏽 **bold**", "clean text unchanged")
    print("selftest ok")
}
