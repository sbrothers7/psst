import AppKit

extension App {
    // MARK: Input + typing guide

    @objc func toggleInput() {
        if name == nil { return showSettings(welcome: true) }
        if input.isVisible { return hideInput() }
        input.orderFrontRegardless()
        input.makeKey()
        input.makeFirstResponder(field)
        updateHints()
    }

    func hideInput() {  // an open menu stays for next time: only Esc closes it
        input.orderOut(nil)
        hints.orderOut(nil)
    }

    func windowDidResignKey(_ n: Notification) { if (n.object as? Panel) === input { hideInput() } }

    func windowWillReturnFieldEditor(_ sender: NSWindow, to client: Any?) -> Any? { (client as? NSTextField) === field ? pairing : nil }

    func controlTextDidChange(_ n: Notification) {
        let long = expand(field.stringValue)  // "/r c " becomes "/room create ", so the guide and quoting see the long form
        if long != field.stringValue {
            field.stringValue = long
            field.currentEditor()?.selectedRange = NSRange(location: (long as NSString).length, length: 0)
        }
        if menu != nil, field.stringValue.hasPrefix("/") { menu = nil }  // a new command gets its own guide, not an old menu behind it
        if let q = quoteDesc(field.stringValue) {
            field.stringValue = q.text
            field.currentEditor()?.selectedRange = NSRange(location: q.cursor, length: 0)
        }
        pick = 0
        updateHints()
        sendTyping()
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy sel: Selector) -> Bool {
        let open = !suggestions.isEmpty, row = open ? suggestions[pick] : nil, text = field.stringValue
        switch sel {
        case #selector(NSResponder.moveUp(_:)) where open:
            pick = (pick + suggestions.count - 1) % suggestions.count
            updateHints()
        case #selector(NSResponder.moveDown(_:)) where open:
            pick = (pick + 1) % suggestions.count
            updateHints()
        case #selector(NSResponder.insertTab(_:)) where open:
            if row!.sub != nil { pickInto(row!) } else { accept() }
        case #selector(NSResponder.deleteBackward(_:)) where textView.selectedRange().length == 0 && emptyPair(text, at: textView.selectedRange().location):
            let both = NSRange(location: textView.selectedRange().location - 1, length: 2)
            if textView.shouldChangeText(in: both, replacementString: "") { textView.replaceCharacters(in: both, with: ""); textView.didChangeText() }
        case #selector(NSResponder.insertNewline(_:)) where NSApp.currentEvent?.modifierFlags.contains(.shift) == true:
            textView.insertNewlineIgnoringFieldEditor(nil)  // Shift+Enter: a new line in the message
        case #selector(NSResponder.insertNewline(_:)):
            if let row, row.sub != nil { pickInto(row); break }  // a person or room: what to do with them
            if let row, !row.run, row.replace != text { accept(); break }  // emoji, #room, a password still to type
            field.stringValue = ""  // commands go like messages: sent, and the field is empty again
            submit(row?.run == true ? row!.replace.trimmingCharacters(in: .whitespaces) : text)
            updateHints()
        case #selector(NSResponder.cancelOperation(_:)):
            if !text.isEmpty, open { suggestions = []; hints.orderOut(nil) }  // typing: put the guide away
            else if menu != nil, text.isEmpty {  // menus close only here, a level at a time
                if menu!.path.isEmpty { menu = nil } else {
                    let back = menu!.path.removeLast()  // highlight who we came from, wherever they are in the list now
                    pick = menuRows(menu!.source, menu!.path, guide).rows.firstIndex { $0.label == back } ?? 0
                }
                updateHints()
            } else { hideInput() }
        default:
            return false
        }
        return true
    }

    /// Opens a command's list as a menu (see listMenu).
    func openList(_ source: String) {
        (menu, pick) = ((source, []), 0)
        updateHints()
    }

    /// Opens the picked row's menu: in a menu, one level down; while typing, the list it came from with this row open.
    func pickInto(_ row: Suggestion) {
        if menu != nil, field.stringValue.isEmpty { menu!.path.append(row.label) }
        else { (menu, field.stringValue) = ((row.replace, [row.label]), "") }
        pick = 0
        updateHints()
    }

    func accept() {
        field.stringValue = suggestions[pick].replace
        field.currentEditor()?.selectedRange = NSRange(location: (field.stringValue as NSString).length, length: 0)
        pick = 0
        updateHints()
    }

    var guide: Ctx {
        Ctx(me: me, room: room, roster: roster, friends: friends, blocked: blocked, changed: changed.keys.sorted(),
            joined: ["public"] + rooms.subtracting(["public"]).sorted(), invited: invited.sorted(), open: openRooms,
            members: room == "public" ? roster : (members[room] ?? [:]).keys.sorted(), nicks: nicks[room] ?? [:],
            requests: requests[room] ?? [], locked: locked.sorted(), descs: roomDescs, types: roomTypes, asks: asks,
            owner: roomOwner[room] ?? "", bans: roomBans[room] ?? [], status: myStatus, busy: busy, aliases: friendNames)
    }

    func updateHints() {
        fitInput()
        let typed = field.stringValue, inMenu = menu != nil && typed.isEmpty  // typing shows the guide; the menu waits
        var title: Suggestion?
        if inMenu {
            let r = menuRows(menu!.source, menu!.path, guide)
            menu!.path = Array(menu!.path.prefix(r.depth))  // a picked row that's gone: back up
            (suggestions, title) = (r.rows, r.title)
        } else { suggestions = suggest(typed, guide) }
        let format = inMenu ? nil : paramGuide(typed, guide)
        guard input.isVisible, inMenu || !suggestions.isEmpty || format != nil else { return hints.orderOut(nil) }
        pick = min(pick, max(suggestions.count - 1, 0))
        let s = NSMutableAttributedString()
        // Columns: ▸ marker | label (+ dot) | detail. Wrapped lines stay under their column instead of the left edge.
        let per = 10, start = pick / per * per, pages = (suggestions.count + per - 1) / per  // a page at a time; arrows flip
        let page = suggestions.enumerated().filter { (start..<start + per).contains($0.offset) }
        let bold = NSFont.systemFont(ofSize: 12, weight: .semibold), indent: CGFloat = 14
        let widest = page.filter { !$0.element.detail.isEmpty }.map { ($0.element.label + ($0.element.dot == nil ? "" : " ●") as NSString).size(withAttributes: [.font: bold]).width }.max() ?? 0
        let col = indent + min(widest, 190) + 16
        let rows = NSMutableParagraphStyle(), head = NSMutableParagraphStyle()
        rows.tabStops = [NSTextTab(textAlignment: .left, location: indent), NSTextTab(textAlignment: .left, location: col)]
        rows.headIndent = col
        head.firstLineHeadIndent = indent
        head.headIndent = indent
        head.paragraphSpacing = 2
        if inMenu {  // the list's command, or the picked person or room; then the way out
            let line = NSMutableAttributedString(attributedString: styled(title?.label ?? menu!.source.trimmingCharacters(in: .whitespaces), bold: true))
            if let on = title?.dot { line.append(styled(on ? " ●" : " ○", color: on ? .systemGreen : .tertiaryLabelColor)) }
            line.append(styled(title == nil ? "   esc to close" : "   esc to go back", dim: true))
            line.addAttribute(.paragraphStyle, value: head, range: NSRange(location: 0, length: line.length))
            s.append(line)
        } else if let format {  // command format, the parameter being typed in accent color
            let line = NSMutableAttributedString(attributedString: styled(format.label, dim: true))
            if let r = format.label.range(of: format.focus) {
                line.addAttributes([.foregroundColor: NSColor.controlAccentColor, .font: bold], range: NSRange(r, in: format.label))
            }
            var at = format.label.startIndex  // red star: a required parameter
            while let r = format.label.range(of: "]*", range: at..<format.label.endIndex) {
                line.addAttributes([.foregroundColor: NSColor.systemRed, .font: bold], range: NSRange(format.label.index(before: r.upperBound)..<r.upperBound, in: format.label))
                at = r.upperBound
            }
            line.append(styled("   " + format.help, dim: true))
            line.addAttribute(.paragraphStyle, value: head, range: NSRange(location: 0, length: line.length))
            s.append(line)
        }
        let body = NSMutableAttributedString()
        for (i, g) in page {
            if body.length > 0 || s.length > 0 { body.append(styled("\n")) }
            body.append(styled((i == pick ? "▸" : "") + "\t" + g.label, dim: i != pick, bold: i == pick))
            if let on = g.dot { body.append(styled(on ? " ●" : " ○", color: on ? .systemGreen : .tertiaryLabelColor)) }
            if !g.detail.isEmpty { body.append(styled("\t" + g.detail, dim: true)) }
            if i == pick, !inMenu, g.sub == nil, g.replace != typed { body.append(styled("  ⇥ tab", color: .tertiaryLabelColor)) }  // Tab completes
        }
        if inMenu, suggestions.isEmpty { body.append(styled("\n\tno one here", dim: true)) }
        if pages > 1 { body.append(styled("\n\tpage \(start / per + 1) of \(pages) · ↑↓", dim: true)) }
        body.addAttribute(.paragraphStyle, value: rows, range: NSRange(location: 0, length: body.length))
        s.append(body)
        hintLabel.attributedStringValue = s
        let h = hintLabel.intrinsicContentSize.height + 10
        hints.setFrame(NSRect(x: input.frame.minX, y: input.frame.maxY + 4, width: 380, height: h), display: true)
        hints.orderFrontRegardless()
    }

    func setRoom(_ r: String) {
        room = r
        field.placeholderString = "#\(r)\(r == "public" ? "" : " 🔒") · / commands · : emoji · **markdown**"
    }

    func submit(_ raw: String) {
        let typed = raw.trimmingCharacters(in: .whitespaces), s = shortForms[typed.lowercased()] ?? expand(typed)
        guard !s.isEmpty else { return }
        let parts = s.split(separator: " ", maxSplits: 1).map(String.init)
        let arg = parts.count > 1 ? parts[1] : ""
        func note(_ text: String) { show(text, dim: true) }
        if let m = menu, asks[m.source]?.contains(where: { $0.replace == s }) == true { (asks[m.source], menu) = (nil, nil) }  // answered
        if let list = listMenu(s), !suggest(list, guide).isEmpty { return openList(list) }  // empty: say so in words below
        if s.hasPrefix("#") {  // "#room message": switch to that room and send there
            let r = clean(String(parts[0].dropFirst()), lower: true)
            if r == "public" || rooms.contains(r) {
                setRoom(r)
                return arg.isEmpty ? note("now in #\(r)") : submit(arg)
            }
            if openRooms[r] != nil { return note("you're not in #\(r). /request \(r) to ask to join") }
        }
        switch parts[0] {  // these work without a host
        case "/quit": return NSApp.terminate(nil)
        case "/settings": return showSettings(welcome: false)
        case "/history":  // on: every message stays and the feed scrolls back; off: they fade. Bare: switch
            let on = arg.isEmpty ? !history : arg.lowercased() == "on"
            setHistory(on)
            if on { line?.send(Msg(t: "history", room: room)) }  // what the host still has, slotted in by time
            return
        case "/friend": return note(friend(arg))
        case "/messages": return setReceive(arg.isEmpty ? !d.bool(forKey: "receive") : arg.lowercased() == "on")
        case "/block":
            let who = clean(arg)
            if who.isEmpty { return note(blocked.isEmpty ? "no one blocked" : "blocked: " + blocked.joined(separator: ", ")) }
            if blocked.contains(who) { blocked.removeAll { $0 == who }; return note("unblocked \(who)") }
            blocked.append(who)
            return note("blocked \(who): you won't see their messages or invites")
        case "/key":
            let who = clean(arg)
            if who.isEmpty { return note("your key: \(fingerprint(publicKey(identity))). Compare in person with /key \(name ?? "you") on their Mac.") }
            guard let k = known[who] else { return note("no key seen for \(who) yet") }
            return note("\(who): \(fingerprint(k))" + (changed[who] != nil ? ". Changed, not trusted. /trust \(who) once it matches" : ""))
        case "/trust":
            let who = clean(arg)
            guard let k = changed.removeValue(forKey: who) else { return note("nothing to trust for \(who)") }
            pins[who] = k
            return note("trusting \(who)'s new key \(fingerprint(k))")
        default: break
        }
        guard let line, !me.isEmpty else { return note("not connected yet: looking for other Macs running Psst") }
        switch parts[0] {
        case "/room":  // create [room name] [type] [desc] · [room name] set [name|desc|password|type] [new] · member [list|kick|ban] [username]
            let what = arg.split(separator: " ").first?.lowercased() ?? ""
            if what == "create" {
                let a = createArgs(String(arg.dropFirst(6)))
                guard !a.room.isEmpty else { return note("/room create [room name] [type] [desc]") }
                guard !reservedRooms.contains(a.room) else { return note("#\(a.room) can't be a room name") }
                return line.send(Msg(t: "create", room: a.room, descs: a.desc.isEmpty ? nil : [a.room: a.desc], types: [a.room: a.type]))
            }
            if what == "member" {  // list: an empty list falls through to here
                let w = arg.split(separator: " ").dropFirst().map(String.init), act = w.first?.lowercased() ?? "list"
                if act == "list" { return note("#\(room): " + guide.members.joined(separator: ", ")) }
                guard act == "kick" || act == "ban", w.count > 1 else { return note("/room member [list|kick|ban] [username]") }
                return line.send(Msg(t: act, room: room, text: w[1]))
            }
            guard let e = roomEdit(arg, current: room) else {
                return note("/room create [room name] · /room [room name] set [name|desc|password|type] [new] · /room member [list|kick|ban] [username]")
            }
            switch e.field {
            case "name": line.send(Msg(t: "rename", room: e.room, text: clean(e.value, lower: true)))
            case "desc": line.send(Msg(t: "desc", room: e.room, text: unquote(Substring(e.value))))
            case "password" where !e.value.isEmpty: line.send(Msg(t: "pass", room: e.room, text: roomPass(e.value)))
            case "type" where Int(e.value).map(typeNames.indices.contains) == true: line.send(Msg(t: "type", room: e.room, text: e.value))
            case "type": note("types: " + typeList)
            default: note("/room [room name] set [name|desc|password|type] [new]")
            }
        case "/browse": note(openRooms.isEmpty ? "No rooms yet. /room create [room name] to make a room." : "rooms: " + openRooms.keys.sorted().map { "#" + $0 }.joined(separator: ", "))
        case "/join":  // /join [room name] [password]
            let w = arg.split(separator: " ", maxSplits: 1).map(String.init), r = w.isEmpty ? "public" : clean(w[0], lower: true)
            if r == "public" || rooms.contains(r) { setRoom(r); note("now in #\(r)") }  // already in: just switch
            else { line.send(Msg(t: "join", room: r, text: w.count > 1 ? roomPass(w[1]) : nil)) }
        case "/request": line.send(Msg(t: "request", room: arg))
        case "/accept":  // this room if anyone is asking here, else the room of the latest request
            line.send(Msg(t: "accept", room: requests[room]?.isEmpty == false ? room : lastAsked ?? room, text: arg))
        case "/nick": line.send(Msg(t: "alias", room: room, text: arg))
        case "/invite": line.send(Msg(t: "invite", room: room, text: arg))
        case "/ping": line.send(Msg(t: "ping", text: arg))
        case "/leave": line.send(Msg(t: "leave", room: room, text: arg.lowercased() == "silent" ? "silent" : nil))
        case "/status":
            guard let n = statusArg(arg) else { return note("you're \(statusNames[myStatus]). /status 0 online · 1 do not disturb · 2 invisible") }
            setStatus(n)
        case "/online": note(arg.isEmpty ? "online: " + roster.map(listed).joined(separator: ", ") : roster.contains(clean(arg)) ? "\(clean(arg)) is online" : "no one online named \(arg)")
        case _ where s.hasPrefix("/"): show(commands.map(usage).joined(separator: " · "), dim: true)
        default:
            let color = d.string(forKey: "color")
            guard room != "public" else { return line.send(Msg(t: "say", room: room, text: emojify(s), color: color)) }
            let to = (members[room] ?? [:]).filter { pins[$0.key] == $0.value }  // only people whose key we trust
            guard let sealed = seal(emojify(s), room: room, from: me, to: to, with: identity)
            else { return note("couldn't encrypt that message") }
            line.send(Msg(t: "say", room: room, ct: sealed.ct, wraps: sealed.wraps, color: color))
        }
    }
}
