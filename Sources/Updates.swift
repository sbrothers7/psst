import AppKit
import CryptoKit

// MARK: - Updates: signed GitHub releases

let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
let repo = "https://github.com/sbrothers7/psst"
let releases = repo + "/releases/latest/download/"  // not the API: no rate limit when many Macs share one IP
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

/// The Updates line in Settings, and whether Update Now applies. `state`: something under way ("Checking…").
func updateText(_ latest: String?, state: String?, current: String = appVersion) -> (text: String, canUpdate: Bool) {
    if let state { return (state, false) }
    guard let latest else { return ("Psst \(current)", false) }
    return isNewer(latest, than: current) ? ("Update available: \(latest)", true) : ("Psst \(current) is up to date", false)
}

extension App {
    // MARK: Updates

    /// With auto update on, installs once the chosen interval has passed since the last look, across restarts.
    /// On launch it always looks, so Settings and the menu can say an update is out.
    func updateIfDue(launch: Bool = false) {
        let now = Date().timeIntervalSince1970, last = d.double(forKey: "lastUpdateCheck")
        let due = d.bool(forKey: "autoUpdate") && (now - last >= d.double(forKey: "updateEvery") || now < last)  // now < last: clock moved back
        if due { d.set(now, forKey: "lastUpdateCheck") }
        if due || launch { checkForUpdate(install: due) }
    }

    /// Asks GitHub for the latest version; `install`: also installs it when it's newer.
    func checkForUpdate(install: Bool) {
        setUpdateState("Checking…")
        var head = URLRequest(url: URL(string: repo + "/releases/latest")!)
        head.httpMethod = "HEAD"
        URLSession.shared.dataTask(with: head) { _, response, _ in  // the version is where it redirects: see tagVersion
            let v = tagVersion(response?.url)
            DispatchQueue.main.async {
                if let v { self.latest = v }
                self.setUpdateState(v == nil ? "Couldn't check for updates" : nil)
                if install, let v, isNewer(v, than: appVersion) { self.download() }
            }
        }.resume()
    }

    func download() {
        setUpdateState("Downloading…")
        DispatchQueue.global().async {
            func get(_ file: String) -> Data? { try? Data(contentsOf: URL(string: releases + file)!) }
            let zip = get("Psst.zip"), sig = get("Psst.zip.sig")
            DispatchQueue.main.async {
                guard let zip, let sig else { return self.setUpdateState("Download failed") }
                self.setUpdateState(nil)
                self.install(zip, sig: sig)
            }
        }
    }

    @objc func checkNow() { checkForUpdate(install: false) }
    @objc func updateNow() { download() }

    func setUpdateState(_ s: String?) {
        updateState = s
        let u = updateText(latest, state: s)
        updateLabel.stringValue = u.text
        updateNowButton.isHidden = !u.canUpdate
        checkButton.isEnabled = s != "Checking…" && s != "Downloading…"
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
}
