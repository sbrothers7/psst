import Foundation
import Network

// MARK: - Host: routes messages, owns rooms, invites and history (memory only)

final class Server {
    struct Client {
        var name = "anon"
        var ready = false  // said hello
        var hidden = false, dnd = false, noPings = false
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
    var lastPing: [String: Double] = [:]   // name -> when they last pinged someone; one ping every 30 s
    var passwords: [String: String] = [:]  // room -> password hash; anyone who has it can join
    var descs: [String: String] = [:]      // room -> description, shown when browsing
    var types: [String: Int] = [:]         // room -> who can get in (see typeNames); none: 0, invite only
    var bans: [String: Set<String>] = [:]  // room -> names its creator banned; they can't get back in
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
        listen(port)
        if advertise { self.advertise(up: "", upSince: .infinity, hops: 0) }
        timers = [.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.purge() },
                  .scheduledTimer(withTimeInterval: 20, repeats: true) { [weak self] _ in  // "still here" for the next in line
                      self?.successors.forEach { self?.clients[$0]?.send(Msg(t: "rep")) } }]
    }

    /// Retries every second while it fails, e.g. while the previous host's listener is still closing after a wake.
    private func listen(_ port: NWEndpoint.Port) {
        let params = tcp()
        params.allowLocalEndpointReuse = true
        guard let l = try? NWListener(using: params, on: port) else { return NSLog("psst: can't listen on \(port)") }
        l.service = listener?.service  // a retry keeps what was advertised
        l.stateUpdateHandler = { [weak self, weak l] state in
            guard case .failed(let e) = state, let l else { return }
            NSLog("psst: listener failed: \(e), retrying")
            l.cancel()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) { if let self, self.listener === l { self.listen(port) } }
        }
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
    }

    /// Tells nearby Macs which host this Mac is on, so ones that can't reach it over Wi-Fi can go through here.
    func advertise(up: String, upSince: Double, hops: Int) {
        listener?.service = NWListener.Service(name: "psst-" + id.prefix(8), type: serviceType, txtRecord: NWTXTRecord(
            ["id": id, "since": String(since), "up": up, "upsince": String(upSince), "hops": String(hops)]))
    }

    func stop() {
        listener?.cancel()
        listener = nil  // ends any retry
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
        bans[room] = nil
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
            let asked = clean(m.from ?? "")
            c.name = unique(validName(asked) ? asked : "", id)  // a modified Psst could skip the name check
            c.hidden = m.hidden ?? false
            c.dnd = m.dnd ?? false
            c.noPings = m.noPings ?? false
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
            guard bans[room]?.contains(c.name) != true else { return note("you're banned from #\(room)") }
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
                if let problem = nameProblem(n) { return note(problem, room) }
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
            guard bans[room]?.contains(name) != true else { return note("\(name) is banned from #\(room): /room member ban \(name) lifts it", room) }
            guard let target = clients.first(where: { $0.value.ready && $0.value.name == name && !$0.value.hidden })
            else { return note("no one named \(name)") }  // invisible people can't be found by name either
            guard !target.value.rooms.contains(room) else { return note("\(name) is already here", room) }
            invites[room, default: []].insert(target.key)
            target.value.send(Msg(t: "invite", room: room, from: c.name))
            note("\(name) was invited to #\(room)")

        case "leave":
            guard room != "public", c.rooms.contains(room) else { return }
            if owners[room] == id { return close(room) }
            remove(id, from: room, note: m.text == "silent" ? nil : "\(c.name) has left #\(room)")

        case "kick", "ban":  // the room's creator only; a ban also keeps them out, and banning again lifts it
            let name = clean(m.text ?? ""), did = m.t == "ban" ? "banned" : "removed"
            guard room != "public", c.rooms.contains(room) else { return note("/join the room first") }
            guard owners[room] == id else { return note("only the room's creator can \(m.t) people", room) }
            guard !name.isEmpty, name != c.name else { return note(name.isEmpty ? "/room member \(m.t) [username]" : "you can't \(m.t) yourself", room) }
            let target = clients.first { $0.value.name == name }?.key
            if m.t == "ban" {
                if bans[room]?.remove(name) != nil {
                    members(room)
                    return send(Msg(t: "note", room: room, text: "\(c.name) lifted \(name)'s ban"), to: room)
                }
                bans[room, default: []].insert(name)
                if let t = target { invites[room]?.remove(t); requests[room]?.removeAll { $0 == t } }
            }
            guard let t = target, clients[t]?.rooms.contains(room) == true else {
                guard m.t == "ban" else { return note("\(name) isn't in #\(room)", room) }
                members(room)
                return send(Msg(t: "note", room: room, text: "\(c.name) banned \(name)"), to: room)
            }
            clients[t]?.send(Msg(t: "note", text: "\(c.name) \(did) you from #\(room)"))
            remove(t, from: room, note: "\(c.name) \(did) \(name) from #\(room)")

        case "ping":  // flashes "ana has pinged you [in #room]" on their screens
            let name = clean(m.text ?? "")
            guard let target = clients.first(where: { $0.key != id && $0.value.ready && $0.value.name == name && !$0.value.hidden })
            else { return note(name == c.name ? "you can't ping yourself" : "no one named \(name)") }
            guard !target.value.dnd else { return note("\(name) is in do not disturb") }
            guard !target.value.noPings else { return note("\(name) turned pings off") }
            let now = Date().timeIntervalSince1970, wait = 30 - (now - (lastPing[c.name] ?? 0))
            guard wait <= 0 else { return note("you can ping again in \(Int(wait.rounded(.up))) s") }
            lastPing[c.name] = now
            target.value.send(Msg(t: "ping", room: room != "public" && c.rooms.contains(room) ? room : nil, from: c.name))
            note("pinged \(name)")

        case "typing":  // passed on, never kept; invisible people don't show up typing in public
            guard c.rooms.contains(room), !(c.hidden && room == "public") else { return }
            let out = Msg(t: "typing", room: room, from: c.name, nick: c.nicks[room])
            for (other, o) in clients where other != id && o.rooms.contains(room) { o.send(out) }

        case "history":
            if c.rooms.contains(room) { replay(room, to: c) }

        case "rename":  // any member, like /invite; everyone in it, invited or asking follows along
            let new = clean(m.text ?? "", lower: true)
            guard room != "public", c.rooms.contains(room) else { return note("/join the room to rename it") }
            guard !new.isEmpty, !reservedRooms.contains(new) else { return note(new.isEmpty ? "/room set name [new]" : "#\(new) can't be a room name", room) }
            guard owners[new] == nil else { return note("#\(new) is taken", room) }
            func move<T>(_ d: inout [String: T]) { if let v = d.removeValue(forKey: room) { d[new] = v } }
            move(&owners); move(&passwords); move(&descs); move(&types); move(&bans); move(&invites); move(&requests); move(&restore)
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

    /// Puts a client in a room (invited, rejoining, or let in after asking). Not someone banned from it.
    func enter(_ id: Int, _ room: String) {
        guard var c = clients[id] else { return }
        guard bans[room]?.contains(c.name) != true else { return c.send(Msg(t: "note", text: "you're banned from #\(room)")) }
        invites[room]?.remove(id)
        requests[room]?.removeAll { $0 == id }
        if c.rooms.insert(room).inserted {
            clients[id] = c
            send(Msg(t: "note", text: "\(c.name) has joined #\(room)"), to: room)
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
            r.bans = bans[room]?.sorted()
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
            bans[room] = r.bans.map(Set.init)
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
        let msg = Msg(t: "who", names: shown.map(\.name).sorted(), busy: shown.filter(\.dnd).map(\.name).sorted(), keys: keys)
        for c in clients.values { c.send(msg) }
    }

    /// Tells a private room's members who is in it and their keys, so they can encrypt to each other.
    /// Who's in a room, with keys and nicknames; also its creator and who is banned, for /room member.
    func members(_ room: String) {
        let inRoom = clients.values.filter { $0.rooms.contains(room) && !$0.key.isEmpty }
        send(Msg(t: "members", room: room, from: owners[room].flatMap { clients[$0]?.name }, names: bans[room]?.sorted(), keys: Dictionary(inRoom.map { ($0.name, $0.key) }, uniquingKeysWith: { a, _ in a }),
                 nicks: Dictionary(inRoom.compactMap { c in c.nicks[room].map { (c.name, $0) } }, uniquingKeysWith: { a, _ in a })), to: room)
    }

    /// Takes someone out of a room: they left, or were kicked or banned. No note: they left silently.
    func remove(_ id: Int, from room: String, note text: String?) {
        guard var c = clients[id], c.rooms.remove(room) != nil else { return }
        c.nicks[room] = nil
        clients[id] = c
        c.send(Msg(t: "left", room: room))
        if let text { send(Msg(t: "note", text: text), to: room) }
        members(room)
        roomList()
    }

    func purge() {
        let now = Date().timeIntervalSince1970
        history.removeAll { ($0.ts ?? 0) < now - retention }
        lastAsk = lastAsk.filter { now - $0.value < 60 }
        lastPing = lastPing.filter { now - $0.value < 30 }
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
