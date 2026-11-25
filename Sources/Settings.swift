import AppKit
import Carbon.HIToolbox
import ServiceManagement

extension App {
    // MARK: Settings, username, friends

    @objc func openSettings() { showSettings(welcome: false) }

    /// welcome = onboarding: the first launch shows the how-to on top of the settings.
    func showSettings(welcome: Bool) {
        if settings == nil { settings = buildSettings() }
        let w = settings!
        welcomeText.isHidden = !welcome
        welcomeText.stringValue = """
            Chat with people on this network. Messages fade away and nothing is saved.
            \(shortcut) opens the chat bar. Type / for commands, :name for emoji, **bold** for markdown.
            Psst finds other Macs running it and connects on its own, no setup needed.
            Drag the bubbles to move them; right-click to lock them in place.
            """
        if welcome { tabs.selectTabViewItem(withIdentifier: "Profile") }
        w.title = welcome ? "Welcome to Psst" : "Psst Settings"
        refreshSettings()
        refreshPeople()
        sizeSettings(w)
        NSApp.activate(ignoringOtherApps: true)
        w.makeKeyAndOrderFront(nil)
        w.makeFirstResponder(nameField.isEnabled ? nameField : nil)
    }

    func buildSettings() -> NSWindow {
        let w = NSWindow(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        w.isReleasedWhenClosed = false
        w.delegate = self
        nameField.placeholderString = "2–20 letters, digits, - or _"
        nameField.target = self  // Enter saves
        nameField.action = #selector(saveName)
        nameField.widthAnchor.constraint(equalToConstant: 180).isActive = true
        saveButton.target = self
        saveButton.action = #selector(saveName)
        nameNote.font = .systemFont(ofSize: 11)
        nameNote.textColor = .secondaryLabelColor
        nameNote.preferredMaxLayoutWidth = 260
        lockBox.target = self
        lockBox.action = #selector(lockChanged)
        loginBox.target = self
        loginBox.action = #selector(loginChanged)
        checkButton.target = self
        checkButton.action = #selector(checkNow)
        updateNowButton.target = self
        updateNowButton.action = #selector(updateNow)
        updateLabel.textColor = .secondaryLabelColor
        updateBox.target = self
        updateBox.action = #selector(updateBoxChanged)
        filterBox.target = self
        filterBox.action = #selector(filterChanged)
        pingsBox.target = self
        pingsBox.action = #selector(pingsChanged)
        mentionBox.target = self
        mentionBox.action = #selector(mentionChanged)
        typingBox.target = self
        typingBox.action = #selector(typingChanged)
        shortcutButton.target = self
        shortcutButton.action = #selector(recordShortcut)
        shortcutButton.title = shortcut
        popups = [
            popup("status", [("Online", 0), ("Do not disturb: no pings or sounds", 1), ("Invisible: not in the online list", 2)]),
            popup("invites", [("Everyone", "everyone"), ("Friends only", "friends"), ("Nobody", "nobody")]),
            popup("cooldown", [("5 seconds", 5.0), ("10 seconds", 10.0), ("30 seconds", 30.0), ("1 minute", 60.0)]),
            popup("retention", [("1 minute", 60.0), ("10 minutes", 600.0), ("1 hour", 3600.0), ("1 day", 86400.0)]),
            popup("color", [("Auto", "auto")] + nameColors.map { ($0.name.capitalized, $0.name) }),
            popup("picKind", [("None", "none"), ("Letters from my name", "letters"), ("Choose a picture…", "image")]),
            popup("updateEvery", [("every hour", 3600.0), ("every 6 hours", 21600.0), ("every 12 hours", 43200.0), ("every day", 86400.0), ("every week", 604800.0)]),
            popup("alignMine", [("On the left", "left"), ("On the right", "right")]),
            popup("alignOthers", [("On the left", "left"), ("On the right", "right")]),
        ]
        picPreview.widthAnchor.constraint(equalToConstant: 28).isActive = true
        picPreview.heightAnchor.constraint(equalToConstant: 28).isActive = true
        for (item, c) in zip(popups[4].itemArray.dropFirst(), nameColors) { item.image = swatch(c.color) }
        func label(_ s: String) -> NSTextField { NSTextField(labelWithString: s) }
        let updates = NSStackView(views: [updateBox, popups[6]])  // ☑ Install automatically, checking [every day]
        updates.alignment = .firstBaseline
        let none = NSGridCell.emptyContentView
        func form(_ rows: [[NSView]]) -> NSGridView {
            let g = NSGridView(views: rows)
            g.column(at: 0).xPlacement = .trailing
            g.rowAlignment = .firstBaseline
            g.rowSpacing = 10
            return g
        }
        let profile = form([
            [label("Username"), NSStackView(views: [nameField, saveButton])],
            [none, nameNote],
            [label("Name color"), popups[4]],
            [label("Profile picture"), NSStackView(views: [popups[5], picPreview])],
        ])
        profile.row(at: 3).rowAlignment = .none  // picture row: centered on the preview, not the popup's baseline
        profile.row(at: 3).yPlacement = .center
        let chat = form([
            [label("Chat shortcut"), shortcutButton],
            [label("Messages fade after"), popups[2]],
            [label("My messages"), popups[7]],
            [label("Others' messages"), popups[8]],
            [none, filterBox],
            [none, typingBox],
            [none, mentionBox],
            [none, lockBox],
        ])
        let privacy = form([
            [label("Status"), popups[0]],
            [none, pingsBox],
            [label("Room invites from"), popups[1]],
            [label("When hosting, erase history after"), popups[3]],
        ])
        let general = form([
            [none, loginBox],
            [label("Updates"), updates],
            [none, NSStackView(views: [updateLabel, checkButton, updateNowButton])],
        ])
        let width = [profile, chat, privacy, general].map(\.fittingSize.width).max()!
        welcomeText.preferredMaxLayoutWidth = width  // wrap to the settings' width
        box.orientation = .vertical
        box.alignment = .leading
        box.spacing = 18
        box.addArrangedSubview(welcomeText)
        box.addArrangedSubview(profile)
        buildPeople(width: width)
        buildAbout()
        let pages: [(String, NSView, Bool)] = [("Profile", box, false), ("Chat", chat, false), ("Privacy", privacy, false),
                                               ("People", peopleBox, false), ("General", general, false), ("About", aboutBox, true)]
        for (title, v, centered) in pages {
            let page = NSView(), item = NSTabViewItem(identifier: title)
            v.translatesAutoresizingMaskIntoConstraints = false
            page.addSubview(v)
            NSLayoutConstraint.activate(centered
                ? [v.centerXAnchor.constraint(equalTo: page.centerXAnchor), v.centerYAnchor.constraint(equalTo: page.centerYAnchor)]
                : [v.leadingAnchor.constraint(equalTo: page.leadingAnchor, constant: 20), v.topAnchor.constraint(equalTo: page.topAnchor, constant: 20)])
            item.label = title
            item.view = page
            tabs.addTabViewItem(item)
        }
        w.contentView!.addSubview(tabs)
        sizeSettings(w)
        w.center()
        return w
    }

    /// The window fits the biggest tab, so switching tabs never resizes it.
    func sizeSettings(_ w: NSWindow) {
        let fit = tabs.tabViewItems.compactMap { $0.view?.subviews.first?.fittingSize }
        let inner = NSSize(width: max(fit.map(\.width).max()!, 420) + 40, height: fit.map(\.height).max()! + 40)  // 420: room for the tabs
        tabs.frame = NSRect(x: 0, y: 0, width: 1000, height: 1000)  // to measure the tab bar and border
        tabs.frame = NSRect(x: 12, y: 12, width: inner.width + 1000 - tabs.contentRect.width,
                            height: inner.height + 1000 - tabs.contentRect.height)
        w.setContentSize(NSSize(width: tabs.frame.width + 24, height: tabs.frame.height + 18))
    }

    func buildPeople(width: CGFloat) {
        peopleScroll.hasVerticalScroller = true
        peopleScroll.borderType = .bezelBorder
        peopleScroll.drawsBackground = false
        peopleScroll.widthAnchor.constraint(equalToConstant: width).isActive = true
        peopleScroll.heightAnchor.constraint(equalToConstant: 220).isActive = true
        let note = NSTextField(wrappingLabelWithString: "Friends and blocks are kept on this Mac only. You won't see messages or invites from people you block.")
        note.font = .systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        note.preferredMaxLayoutWidth = width
        peopleBox.orientation = .vertical
        peopleBox.alignment = .leading
        peopleBox.spacing = 10
        [peopleNote, peopleScroll, note].forEach(peopleBox.addArrangedSubview)
    }

    /// Everyone online here, plus friends and blocked people who aren't; online first.
    func refreshPeople() {
        let online = Set(roster), mine = [me, name ?? ""]
        let list = Set(roster + friends + blocked).subtracting(mine).sorted {
            (online.contains($0) ? 0 : 1, $0.lowercased()) < (online.contains($1) ? 0 : 1, $1.lowercased())
        }
        let here = roster.filter { !mine.contains($0) }.count
        peopleNote.stringValue = me.isEmpty ? "Not connected yet: looking for other Macs running Psst."
            : here == 0 ? "No one else is online on this network yet." : "\(here) online on this network"
        func small(_ s: String) -> NSTextField {
            let l = NSTextField(labelWithString: s)
            l.font = .systemFont(ofSize: 11)
            l.textColor = .secondaryLabelColor
            return l
        }
        func check(_ who: String, _ on: Bool, _ tag: Int) -> NSButton {
            let b = NSButton(checkboxWithTitle: "", target: self, action: #selector(personToggled))
            b.state = on ? .on : .off
            b.identifier = NSUserInterfaceItemIdentifier(who)
            b.tag = tag  // 0 friend, 1 blocked
            return b
        }
        let rows: [[NSView]] = list.isEmpty ? [[small("People show up here once they open Psst on this network.")]]
            : [[small("Name"), small("Friend"), small("Blocked")]] + list.map { who in
                let t = NSMutableAttributedString(string: who, attributes: [.font: NSFont.systemFont(ofSize: 13), .foregroundColor: NSColor.labelColor])
                let on = online.contains(who)
                t.append(NSAttributedString(string: on ? "  ●" : "  ○", attributes: [.font: NSFont.systemFont(ofSize: 11),
                    .foregroundColor: on ? NSColor.systemGreen : NSColor.tertiaryLabelColor]))
                return [NSTextField(labelWithAttributedString: t), check(who, friends.contains(who), 0), check(who, blocked.contains(who), 1)]
            }
        let g = NSGridView(views: rows)
        g.rowSpacing = 6
        g.columnSpacing = 24
        g.rowAlignment = .firstBaseline
        if !list.isEmpty { for c in 1...2 { g.column(at: c).xPlacement = .center } }
        g.frame = NSRect(origin: NSPoint(x: 10, y: 8), size: g.fittingSize)
        let doc = Flipped(frame: NSRect(x: 0, y: 0, width: g.frame.maxX + 10, height: g.frame.maxY + 8))
        doc.addSubview(g)
        peopleScroll.documentView = doc
    }

    @objc func personToggled(_ b: NSButton) {
        guard let who = b.identifier?.rawValue else { return }
        if b.tag == 0 { friends.removeAll { $0 == who }; if b.state == .on { friends.append(who) } }
        else { blocked.removeAll { $0 == who }; if b.state == .on { blocked.append(who) } }
    }

    func buildAbout() {
        let icon = NSImageView(image: NSApp.applicationIconImage)
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.widthAnchor.constraint(equalToConstant: 96).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 96).isActive = true
        let title = NSTextField(labelWithString: "Psst")
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        let version = NSTextField(labelWithString: "Version \(appVersion)")
        version.textColor = .secondaryLabelColor
        let credits = NSTextField(labelWithString: "by sbrothers7")
        credits.font = .systemFont(ofSize: 11)
        credits.textColor = .secondaryLabelColor
        let link = NSButton(title: "", target: self, action: #selector(openRepo))
        link.isBordered = false
        link.attributedTitle = NSAttributedString(string: repo.replacingOccurrences(of: "https://", with: ""),
                                                  attributes: [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.linkColor])
        aboutBox.orientation = .vertical
        aboutBox.alignment = .centerX
        aboutBox.spacing = 4
        [icon, title, version, NSTextField(labelWithString: "A tiny LAN chat overlay for Macs."), credits, link].forEach(aboutBox.addArrangedSubview)
        aboutBox.setCustomSpacing(10, after: icon)
        aboutBox.setCustomSpacing(14, after: version)
    }

    @objc func openRepo() { NSWorkspace.shared.open(URL(string: repo)!) }

    func popup(_ key: String, _ opts: [(String, Any)]) -> NSPopUpButton {
        let p = NSPopUpButton()
        p.identifier = NSUserInterfaceItemIdentifier(key)
        p.target = self
        p.action = #selector(popupChanged(_:))
        for (title, v) in opts {
            p.addItem(withTitle: title)
            p.lastItem?.representedObject = v
        }
        return p
    }

    func refreshSettings() {
        let left = nameChangeLeft(since: d.object(forKey: "nameSetAt") as? Date)
        nameField.stringValue = name ?? ""
        nameField.isEnabled = name == nil || left == 0
        saveButton.isEnabled = nameField.isEnabled
        nameNote.stringValue = name == nil ? "Pick the name others will see. After this you can change it once every 2 weeks."
            : left > 0 ? "You can change your name again in \(waitText(left))."
            : "You can change your name now, then not again for 2 weeks."
        for p in popups {
            let current = d.object(forKey: p.identifier!.rawValue) as? NSObject
            p.selectItem(at: p.itemArray.firstIndex { ($0.representedObject as? NSObject)?.isEqual(current) == true } ?? 0)
        }
        lockBox.state = d.bool(forKey: "locked") ? .on : .off
        filterBox.state = d.bool(forKey: "filter") ? .on : .off
        typingBox.state = d.bool(forKey: "typing") ? .on : .off
        mentionBox.state = d.bool(forKey: "mentionSound") ? .on : .off
        pingsBox.state = d.bool(forKey: "pings") ? .on : .off
        updateBox.state = d.bool(forKey: "autoUpdate") ? .on : .off
        setUpdateState(updateState)
        popups[6].isEnabled = updateBox.state == .on
        if #available(macOS 13, *) { loginBox.state = SMAppService.mainApp.status == .enabled ? .on : .off } else {
            loginBox.isEnabled = false
            loginBox.title = "Open Psst at login (needs macOS 13; use System Preferences › Login Items)"
        }
        popups[4].itemArray.first?.image = swatch(nameColor(name ?? "", nil))  // what Auto gives this name
        picPreview.image = avatarImage(myPic, name: name ?? "", color: nameColor(name ?? "", d.string(forKey: "color")), side: 28)
        picPreview.isHidden = picPreview.image == nil
        shortcutButton.title = shortcut
    }

    func swatch(_ c: NSColor) -> NSImage {
        NSImage(size: NSSize(width: 10, height: 10), flipped: false) { r in c.setFill(); NSBezierPath(ovalIn: r).fill(); return true }
    }

    /// Click, then press the new keys. Esc cancels. The old shortcut is off meanwhile so it can be typed again.
    @objc func recordShortcut() {
        guard recorder == nil else { return }
        if let hotKey { UnregisterEventHotKey(hotKey) }
        hotKey = nil
        shortcutButton.title = "Press keys… (Esc cancels)"
        recorder = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] e in
            guard let self else { return e }
            let code = Int(e.keyCode)
            if code != kVK_Escape {
                guard let spec = hotKeySpec(e.modifierFlags, key: code, chars: e.charactersIgnoringModifiers ?? "") else {
                    self.shortcutButton.title = "Use ⌃ or ⌥ with a key"
                    return nil
                }
                if self.bindHotKey(code, spec.mods) {
                    self.d.set(code, forKey: "hotKeyCode")
                    self.d.set(spec.mods, forKey: "hotKeyMods")
                    self.d.set(spec.label, forKey: "hotKeyLabel")
                } else {
                    self.nameNote.stringValue = "\(spec.label) is taken by another app."
                }
            }
            self.stopRecording()
            return nil
        }
    }

    func stopRecording() {
        guard let r = recorder else { return }
        NSEvent.removeMonitor(r)
        recorder = nil
        if hotKey == nil { _ = bindHotKey(d.integer(forKey: "hotKeyCode"), d.integer(forKey: "hotKeyMods")) }  // cancelled or taken: keep the old one
        shortcutButton.title = shortcut
    }

    func waitText(_ s: TimeInterval) -> String {
        s > 86400 ? "\(Int((s / 86400).rounded(.up))) days" : "\(Int((s / 3600).rounded(.up))) hours"
    }

    @objc func popupChanged(_ p: NSPopUpButton) {
        let key = p.identifier!.rawValue, old = d.object(forKey: key)
        d.set(p.selectedItem?.representedObject, forKey: key)
        if key == "retention" { server?.retention = d.double(forKey: key); server?.purge() }
        if key == "status" { sendProfile() }
        if key == "color" { refreshSettings() }  // the letters picture takes the name color
        if key == "picKind" { picChanged(old: old) }
    }

    var myPic: String {  // what others see beside my messages
        switch d.string(forKey: "picKind") {
        case "letters": return "letters"
        case "image": return d.data(forKey: "picData")?.base64EncodedString() ?? ""
        default: return ""
        }
    }

    func sendProfile() { line?.send(Msg(t: "nick", from: name, hidden: myStatus == 2, dnd: myStatus == 1, noPings: !d.bool(forKey: "pings"), key: publicKey(identity), pic: myPic)) }

    /// "Choose a picture…" asks for an image; cancelling goes back to what was set before.
    func picChanged(old: Any?) {
        guard d.string(forKey: "picKind") == "image", let w = settings else { refreshSettings(); return sendProfile() }
        let o = NSOpenPanel()
        o.allowedContentTypes = [.image]
        o.beginSheetModal(for: w) { [weak self] r in
            guard let self else { return }
            if r == .OK, let url = o.url, let img = NSImage(contentsOf: url), let jpg = squareJPEG(img) { self.d.set(jpg, forKey: "picData") }
            else { self.d.set(old, forKey: "picKind") }
            self.refreshSettings()
            self.sendProfile()
        }
    }

    @objc func updateBoxChanged() {
        d.set(updateBox.state == .on, forKey: "autoUpdate")
        popups[6].isEnabled = updateBox.state == .on
        updateIfDue()
    }

    @objc func filterChanged() { d.set(filterBox.state == .on, forKey: "filter") }

    @objc func pingsChanged() {
        d.set(pingsBox.state == .on, forKey: "pings")
        sendProfile()
    }

    /// /status: 0 online, 1 do not disturb, 2 invisible (see statusNames).
    func setStatus(_ n: Int) {
        d.set(n, forKey: "status")
        sendProfile()
        if settings != nil { refreshSettings() }
        show("you're \(statusNames[n])" + (n == 1 ? ": no pings or mention sounds" : n == 2 ? ": hidden from the online list" : ""), dim: true)
    }

    @objc func mentionChanged() { d.set(mentionBox.state == .on, forKey: "mentionSound") }

    @objc func typingChanged() {
        d.set(typingBox.state == .on, forKey: "typing")
        typers = [:]
        showTyping()
    }

    @objc func lockChanged() {
        d.set(lockBox.state == .on, forKey: "locked")
        applyLock()
    }

    @objc func saveName() {
        let first = name == nil
        let result = setName(nameField.stringValue)
        refreshSettings()
        nameNote.stringValue = result
        if first, name != nil { askLoginItem() }  // setup: once the username is picked
    }

    @objc func loginChanged() { setLoginItem(loginBox.state == .on) }

    func setLoginItem(_ on: Bool) {
        guard #available(macOS 13, *) else { return }
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            if SMAppService.mainApp.status == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }  // macOS wants a yes
        } catch {
            show("couldn't change Open at Login: \(error.localizedDescription)", dim: true)
        }
        refreshSettings()
    }

    func askLoginItem() {
        guard #available(macOS 13, *), SMAppService.mainApp.status != .enabled, let w = settings else { return }
        let a = NSAlert()
        a.messageText = "Open Psst when you log in?"
        a.informativeText = "Then you're reachable without starting it every day. You can change this in Settings."
        a.addButton(withTitle: "Open at Login")
        a.addButton(withTitle: "Not Now")
        a.beginSheetModal(for: w) { [weak self] r in if r == .alertFirstButtonReturn { self?.setLoginItem(true) } }
    }

    func windowWillClose(_ n: Notification) {
        guard (n.object as? NSWindow) === settings else { return }
        stopRecording()
        NSApp.deactivate()  // hand focus back to whatever was in front
    }

    /// Sets the username if the 2-week rule allows. Returns what happened, for the user.
    func setName(_ raw: String) -> String {
        let n = raw.trimmingCharacters(in: .whitespaces)
        if let problem = nameProblem(n) { return problem }
        guard n != name else { return "That's already your name." }
        let left = nameChangeLeft(since: d.object(forKey: "nameSetAt") as? Date)
        guard name == nil || left == 0 else { return "You can change your name again in \(waitText(left))." }
        d.set(n, forKey: "name")
        d.set(Date(), forKey: "nameSetAt")
        if line != nil { sendProfile() } else { connect() }
        return "Saved: you're \(n). \(shortcut) to chat. Next name change in 2 weeks."
    }

    /// /friend [list|add|remove] [username]. Friends are kept on this Mac only.
    func friend(_ arg: String) -> String {
        let w = arg.split(separator: " ").map(String.init)
        let who = w.count > 1 ? clean(w[1]) : ""
        switch (w.first ?? "list", who.isEmpty) {
        case ("list", _):
            let online = friends.filter(roster.contains)
            return friends.isEmpty ? "no friends yet: /friend add [username]"
                : online.isEmpty ? "no friends online" : "friends online: " + online.joined(separator: ", ")
        case ("add", false):
            guard who != me, who != name else { return "that's you" }
            if !friends.contains(who) { friends.append(who) }
            return "added \(who) to friends" + (roster.contains(who) ? " (online now)" : "")
        case ("remove", false):
            friends.removeAll { $0 == who }
            return "removed \(who) from friends"
        default:
            return "/friend list · /friend add [username] · /friend remove [username]"
        }
    }

    @objc func invite(_ i: NSMenuItem) { line?.send(Msg(t: "invite", room: room, text: i.representedObject as? String)) }
}
