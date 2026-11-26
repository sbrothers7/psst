import CryptoKit
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
/// the network keeps Macs apart (client isolation, or a VPN that captures local traffic), so Psst reaches Macs
/// within ~30 m, and others through them. `links`: interface names each other Mac was found on. No other Mac found: can't tell, false.
// ponytail: a VPN that passes Bonjour but drops the connections themselves goes unnoticed.
func onlyWiFi(_ links: [[String]]) -> Bool {
    !links.isEmpty && links.allSatisfy { $0.allSatisfy { $0.hasPrefix("awdl") || $0.hasPrefix("llw") } }
}

// MARK: - Network addresses: for networks that drop Bonjour but still let Macs connect
//
// Each Mac tells the host its addresses; the host passes on its own and the next two in line's (see shareAddrs),
// and each Mac remembers them and asks each one on its own network which host it's on (see probePeers), as
// Bonjour would have told it.

typealias Net = (addr: UInt32, mask: UInt32)

/// This Mac's IPv4 addresses and netmasks on Wi-Fi and Ethernet (en*): not loopback, VPN, peer-to-peer or self-assigned.
// ponytail: IPv4 only; add IPv6 if a network turns out to be IPv6-only.
func localNets() -> [Net] {
    var list: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&list) == 0, let start = list else { return [] }
    defer { freeifaddrs(start) }
    func v4(_ s: UnsafeMutablePointer<sockaddr>) -> UInt32 {
        s.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
    }
    return sequence(first: start) { $0.pointee.ifa_next }.compactMap { p in
        let i = p.pointee, up = UInt32(IFF_UP | IFF_RUNNING)
        guard String(cString: i.ifa_name).hasPrefix("en"), i.ifa_flags & up == up, let a = i.ifa_addr, let m = i.ifa_netmask,
              a.pointee.sa_family == sa_family_t(AF_INET), v4(a) >> 16 != 0xA9FE else { return nil }  // 169.254: no network
        return (v4(a), v4(m))
    }
}

func ipv4(_ s: String) -> UInt32? {
    let parts = s.split(separator: ".", omittingEmptySubsequences: false).map { UInt8($0) }
    guard parts.count == 4, !parts.contains(nil) else { return nil }
    return parts.reduce(0) { $0 << 8 | UInt32($1!) }
}

func dotted(_ ip: UInt32) -> String { [24, 16, 8, 0].map { String(ip >> $0 & 255) }.joined(separator: ".") }

/// Of `addrs`, the ones on a network this Mac is on, other than its own: worth asking directly.
/// Other networks are skipped, so addresses remembered at school aren't tried at home.
func onMyNetworks(_ addrs: [String], _ nets: [Net]) -> [String] {
    addrs.compactMap(ipv4).filter { ip in
        !nets.contains { $0.addr == ip } && nets.contains { $0.addr & $0.mask == ip & $0.mask }
    }.map(dotted)
}

/// A HostAd from a Bonjour TXT record, or the same fields sent over a direct connection ("ad", from `addr`).
/// nil for an older Psst: it can't talk to this one (see wireVersion).
func hostAd(_ t: [String: String], addr: String = "") -> HostAd? {
    guard t["v"] == wireVersion, let id = t["id"], let since = t["since"].flatMap(Double.init) else { return nil }
    return HostAd(id: id, since: since, up: t["up"] ?? "", upSince: t["upsince"].flatMap(Double.init) ?? .infinity,
                  hops: t["hops"].flatMap(Int.init) ?? maxHops, addr: addr)
}

// MARK: - Hosting: every Mac hosts, everyone shares the oldest
//
// Every Mac runs a host and advertises it. All Macs join the same one, the longest-running host still reachable,
// so no one has to type /host and a restarted Mac never splits the group. The host keeps the next two in line
// supplied with a copy of its rooms and recent messages; if it disappears they're elected next and carry on.
// Macs out of Wi-Fi range of the host reach it through a Mac in between (up to 3 hops).

/// A Mac as seen over Bonjour. `since` = when its host started. `up` = the host it is connected to right now
/// (maybe one this Mac can't see) and `hops` how many Macs away that is: 0 = itself, 1 = direct.
/// `addr`: the network address it answered on, when found by asking instead of over Bonjour.
struct HostAd: Equatable { var id: String, since: Double, up = "", upSince = Double.infinity, hops = 0, addr = "" }

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
    var addrs: [String]? = nil        // hello: my network addresses; addrs: where the next host can be (see shareAddrs)
    var ad: [String: String]? = nil   // ad: a host's advert (see Server.advertise), asked for directly
}

// MARK: - Wire: one TCP connection, encrypted
//
// Each side's first line is a fresh Curve25519 public key; every line after is one JSON Msg sealed with ChaChaPoly,
// in base64. Someone watching the network sees which Macs talk, never what they say: names, messages, addresses.
// Nothing proves who is at the other end (private rooms check that themselves), so someone sitting in the middle
// of a connection and passing it on could still read it. Psst before this can't talk to it (see wireVersion).

let wireVersion = "2"  // in every advert; Macs without it speak plain JSON and are left out of the election

/// Both ends of a Line derive the same key from the two public keys; anyone else gets a different one.
func lineKey(_ mine: Curve25519.KeyAgreement.PrivateKey, _ theirs: Curve25519.KeyAgreement.PublicKey) -> SymmetricKey? {
    guard let shared = try? mine.sharedSecretFromKeyAgreement(with: theirs) else { return nil }
    let pubs = [mine.publicKey.rawRepresentation, theirs.rawRepresentation].sorted { $0.lexicographicallyPrecedes($1) }
    return shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data("psst line".utf8), sharedInfo: pubs[0] + pubs[1], outputByteCount: 32)
}

final class Line {
    let conn: NWConnection
    var onMsg: (Msg) -> Void = { _ in }
    var onClose: () -> Void = {}
    private var buf = Data(), closed = false, dead = false
    private let mine = Curve25519.KeyAgreement.PrivateKey()
    private var key: SymmetricKey?, queued: [Msg] = []  // sent before the other side's key arrived

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
        write(Data(mine.publicKey.rawRepresentation.base64EncodedString().utf8))
        read()
    }

    func send(_ m: Msg) {
        guard !closed, !dead else { return }
        guard let key else { return queued.append(m) }
        guard let json = try? JSONEncoder().encode(m), let box = try? ChaChaPoly.seal(json, using: key).combined else { return }
        write(Data(box.base64EncodedString().utf8))
    }

    func close() {
        dead = true  // nothing more in or out
        conn.cancel()
    }

    private func write(_ line: Data) { conn.send(content: line + [10], completion: .idempotent) }

    private func finish() {
        guard !closed else { return }
        closed = true
        onClose()
    }

    /// The other side's first line is its key; each line after is one sealed message. Anything else ends the line.
    private func got(_ line: Data) {
        guard let raw = Data(base64Encoded: line) else { return close() }
        guard let key else {
            guard let theirs = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw), let k = lineKey(mine, theirs) else { return close() }
            self.key = k
            let waiting = queued
            queued = []
            waiting.forEach(send)
            return
        }
        guard let box = try? ChaChaPoly.SealedBox(combined: raw), let json = try? ChaChaPoly.open(box, using: key) else { return close() }
        if let m = try? JSONDecoder().decode(Msg.self, from: json) { onMsg(m) }
    }

    private func read() {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, error in
            guard let self, !self.closed else { return }
            if let data { self.buf.append(data) }
            while !self.dead, let i = self.buf.firstIndex(of: 10) {
                let line = Data(self.buf[self.buf.startIndex..<i])
                self.buf = Data(self.buf[(i + 1)...])
                self.got(line)
            }
            // a sealed line is base64 of a JSON line of up to maxLine, plus nonce and tag
            if done || error != nil || self.dead || self.buf.count > maxLine * 4 / 3 + 64 { self.close() } else { self.read() }
        }
    }
}
