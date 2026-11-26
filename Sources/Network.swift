import Foundation
import Network

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

/// True when every other Mac is found only over peer-to-peer Wi-Fi (awdl/llw links), never over the network:
/// the network keeps Macs apart (client isolation, or a VPN that captures local traffic), so Psst reaches only
/// Macs within ~30 m. `links`: interface names each other Mac was found on. No other Mac found: can't tell, false.
// ponytail: a VPN that passes Bonjour but drops the connections themselves goes unnoticed.
func onlyWiFi(_ links: [[String]]) -> Bool {
    !links.isEmpty && links.allSatisfy { $0.allSatisfy { $0.hasPrefix("awdl") || $0.hasPrefix("llw") } }
}

// MARK: - Hosting: every Mac hosts, everyone shares the oldest
//
// Every Mac runs a host and advertises it. All Macs join the same one, the longest-running host still reachable,
// so no one has to type /host and a restarted Mac never splits the group. The host keeps the next two in line
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
        var bans: [String]?  // names kept out by the creator
    }
    var rooms: [String: Room] = [:]
}

struct Msg: Codable {
    var t: String
    var room: String? = nil
    var from: String? = nil
    var text: String? = nil
    var names: [String]? = nil
    var ts: Double? = nil
    var hidden: Bool? = nil           // hello/nick: keep me off the online list
    var dnd: Bool? = nil              // hello/nick: do not disturb: no pings, no sounds
    var noPings: Bool? = nil          // hello/nick: I turned pings off
    var busy: [String]? = nil         // who: people in do not disturb
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
    var tag: String? = nil            // hello/nick: my permanent 4-digit tag; the host shows me as name#tag
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
