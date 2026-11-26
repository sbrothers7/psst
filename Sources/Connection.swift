import AppKit
import Network

extension App {
    // MARK: Connection

    func got(_ m: Msg) {
        defer { if menu != nil { updateHints() } }  // an open menu shows who's online now
        let r = m.room ?? "public", tag = r == "public" ? "" : "#\(r) ", from = m.from ?? "?"
        if blocked.contains(from), ["say", "invite", "request", "ping", "typing"].contains(m.t) { return }
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
            busy = m.busy ?? []
            learn(m.keys ?? [:])
            if settings?.isVisible == true { refreshPeople() }
        case "members":
            members[r] = m.keys ?? [:]
            nicks[r] = m.nicks ?? [:]
            roomOwner[r] = m.from
            roomBans[r] = m.names ?? []
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
            show("\(shown(from)) invited you to #\(r). /join \(r)")
        case "note": show(tag + (m.text ?? ""), dim: true)
        case "typing": gotTyping(m)
        case "ping":
            guard myStatus != 1, d.bool(forKey: "pings") else { break }  // the host checks too; an older one doesn't
            let text = "\(shown(from)) has pinged you" + (r == "public" ? "" : " in #\(r)")
            flashPing(text)
            show(text, dim: true)
        case "say":
            lastSeen = max(lastSeen, m.ts ?? 0)
            if typers.removeValue(forKey: "\(r) \(from)") != nil { showTyping() }
            guard d.bool(forKey: "receive") || from == me else { return }  // /messages off: online, but nothing new shows
            guard seen.insert("\(m.ts ?? 0) \(from)").inserted else { return }  // replays repeat what's on screen
            var text = m.text ?? ""
            if r != "public" {  // private: must open with the sender's trusted key, or it isn't shown
                guard let ct = m.ct, let wrap = m.wraps?[me], let key = members[r]?[from] ?? known[from], pins[from] == key,
                      let opened = open(ct: ct, wrap: wrap, room: r, from: from, senderKey: key, with: identity) else { return }
                text = opened
            }
            showMessage(m, text: markdown(d.bool(forKey: "filter") ? censor(text) : text))
            if from != me, hints.isVisible { menu = nil; suggestions = []; hints.orderOut(nil) }  // don't cover it; typing brings the guide back
            if from != me, myStatus != 1, d.bool(forKey: "mentionSound"), mentions(text, [me] + [nicks[r]?[me]].compactMap { $0 }) {
                NSSound(named: "Glass")?.play()
            }
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
            if pin {  // a Mac is often reachable over several links (Wi-Fi, peer-to-peer); each retry pins the next,
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
        l.send(Msg(t: "hello", from: name, ts: lastSeen, hidden: myStatus == 2, dnd: myStatus == 1, noPings: !d.bool(forKey: "pings"), key: publicKey(identity),
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
}
