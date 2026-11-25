import CryptoKit
import Foundation

// MARK: - End-to-end encryption (private rooms)
//
// Each Mac has a long-lived X25519 key. A private-room message is sealed once with a fresh key K (ChaCha20-Poly1305);
// K is then sealed for each member with the key derived from sender × member. The member copy authenticates the room,
// the sender's name and a hash of the ciphertext, so a host that edits, moves or relabels a message makes it fail to open.
// ponytail: static keys, so no forward secrecy; a stolen identity file opens old captured messages. Fine for casual LAN chat.

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
