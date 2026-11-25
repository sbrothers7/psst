import AppKit

// MARK: - Typing indicator
//
// While someone types a message, the rest of that room sees "ana is typing…" at the bottom of the feed, until they
// send or stop for 5 s. The "typing" setting turns both directions off: nothing sent, nothing shown.

extension App {
    /// Tells the room I'm typing in, at most every 3 s. Not for commands, and not in public while invisible.
    func sendTyping() {
        let t = field.stringValue
        guard d.bool(forKey: "typing"), let line, !t.isEmpty, !t.hasPrefix("/"),
              Date().timeIntervalSince(typingSentAt) > 3 else { return }
        let to = t.hasPrefix("#") && t.contains(" ") ? clean(String(t.dropFirst().prefix { $0 != " " }), lower: true) : room
        guard to != "public" || myStatus != 2 else { return }
        typingSentAt = Date()
        line.send(Msg(t: "typing", room: to))
    }

    func gotTyping(_ m: Msg) {
        guard d.bool(forKey: "typing"), let from = m.from, from != me, !blocked.contains(from) else { return }
        let r = m.room ?? "public"
        typers["\(r) \(from)"] = ((m.nick ?? from) + (r == "public" ? "" : " in #\(r)"), Date() + 5)
        showTyping()
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.1) { [weak self] in self?.showTyping() }
    }

    /// Redraws the indicator, dropping anyone who stopped typing.
    func showTyping() {
        typers = typers.filter { $0.value.until > Date() }
        if let row = typingRow { drop(row) }
        typingRow = nil
        let who = typers.values.map(\.label).sorted()
        guard !who.isEmpty else { return }
        let text = who.joined(separator: ", ") + (who.count == 1 ? " is typing…" : " are typing…")
        typingRow = addRow(bubble(styled(text, dim: true)), right: false, ts: .greatestFiniteMagnitude, keep: true)
    }
}
