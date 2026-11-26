import AppKit
import SwiftUI

// MARK: - Help page (/help, the menu's Help…)
//
// More than the guide's one line: what each command does in full, with examples, then keys, typing and symbols.
// Each command's format and one-line help come from `commands`; the selftest checks every command is here once.

let helpGroups: [(title: String, names: [String])] = [
    ("People", ["/online", "/status", "/ping", "/friend", "/block"]),
    ("Rooms", ["/room", "/browse", "/join", "/request", "/accept", "/invite", "/leave", "/nick"]),
    ("Chat", ["/history", "/messages"]),
    ("Keys and trust", ["/key", "/trust"]),
    ("App", ["/help", "/settings", "/quit"]),
]

/// Markdown: `code` and **bold** show as such.
let commandDetails: [String: (text: String, examples: [String])] = [
    "/online": ("Lists everyone online, friends first. Pick a person for what you can do with them: add a friend, ping, block, or check their key. With a username, says whether they're online. People who are invisible aren't listed.",
                ["/online", "/online ana"]),
    "/status": ("`0` online. `1` do not disturb: no pings or mention sounds, and others see a red dot by your name. `2` invisible: you're left out of the online list but can still chat. Names work too: `dnd`, `invisible`. Also in Settings > Privacy.",
                ["/status 1", "/status dnd"]),
    "/ping": ("Shows \"[your name] has pinged you\" at the top of their screen, with the room if you're in one. Once every 30 seconds. Not for people in do not disturb or who turned pings off in Settings.",
              ["/ping ana"]),
    "/friend": ("Friends come first in lists and have a ★. `rename` gives a friend a nickname only you see, in messages and lists; leave the nickname out to clear it. Friends are kept on this Mac only.",
                ["/friend add ana", "/friend rename ana Bestie", "/friend remove ana"]),
    "/block": ("Hides someone's messages, invites, join requests, pings and typing from you. Again to unblock. With no username, lists who's blocked. Kept on this Mac only.",
               ["/block ana", "/block"]),
    "/room": ("`create [room name] [type] [desc]` makes a room; types: `0` invite only (default), `1` password only, `2` invite or password, `3` open access. `set name|desc|password|type` changes a room you're in (leave out the room name for this one). `member list` shows who's in it; its creator can `member kick` or `member ban` (ban again to lift). A room closes when its creator leaves. Private rooms are end-to-end encrypted.",
              ["/r c chess 3 \"weekend chess\"", "/room set password hunter2", "/room member kick ana"]),
    "/browse": ("Lists the rooms on the network with how many people are in each. Pick one to join or ask to join.",
                ["/browse"]),
    "/join": ("Switches to a room you're in, or joins one you're invited to or have the password for. With no room name, back to public.",
              ["/j chess", "/join chess hunter2", "/join"]),
    "/request": ("Asks to join a room; its members see the request and can let you in with /accept. Once a minute.",
                 ["/rq chess"]),
    "/accept": ("Lets in someone asking to join this room. With no username, the latest request; `all` lets everyone in.",
                ["/a", "/accept ana", "/accept all"]),
    "/invite": ("Invites someone to the room you're in; they join with /join. Who can invite you is set in Settings > Privacy.",
                ["/i ana"]),
    "/leave": ("Leaves the room you're in and tells it you left. `silent` leaves without telling. If you made the room, it closes.",
               ["/leave", "/leave silent"]),
    "/nick": ("Your name in the room you're in only. With no nickname, clears it.",
              ["/nick Captain", "/nick"]),
    "/history": ("`on` (`1`) keeps every message and lets you scroll back, starting with what the host still has. `off` (`0`) lets messages fade after a few seconds; Settings > Chat sets how long. No argument switches.",
                 ["/history on", "/history 0"]),
    "/messages": ("`off` (`0`) keeps you online but shows nothing new, typing included, until `on` (`1`). Also in the menu and Settings > Chat. No argument switches.",
                  ["/m 0", "/messages on"]),
    "/help": ("This page. With a command, opens it at that command.",
              ["/help", "/help room"]),
    "/settings": ("Username, picture, chat bar shortcut, how messages look, privacy, people, updates.",
                  ["/settings"]),
    "/key": ("Shows a code for someone's key, to compare in person on both Macs. With no username, yours. Matching codes mean no one is in the middle.",
             ["/key ana", "/key"]),
    "/trust": ("When someone's key changes (a new Mac, or someone in the middle), Psst warns you and stops encrypting private-room messages to them. Compare /key codes in person, then trust the new key.",
               ["/trust ana"]),
    "/quit": ("Quits Psst. ⌘Q in the chat bar does the same.",
              ["/quit"]),
]

/// The short forms that reach a command, e.g. /r and /r c for /room.
func shortcuts(_ name: String) -> [String] {
    shortForms.filter { $0.value == name }.keys.sorted() + (name == "/room" ? ["/r c"] : [])
}

/// (shown, color of a dot before it, meaning)
func helpTopics(shortcut: String) -> [(title: String, rows: [(key: String, dot: Color?, text: String)])] {
    [("Keys", [(shortcut, nil, "open or close the chat bar (change it in Settings > Chat)"),
               ("Enter", nil, "send; in a list, pick the row"),
               ("Shift + Enter", nil, "new line"),
               ("Tab", nil, "accept the highlighted suggestion"),
               ("↑ ↓", nil, "move through suggestions and lists"),
               ("Esc", nil, "back a level, put the guide away, or close the chat bar"),
               ("⌘Q", nil, "quit")]),
     ("Typing", [("/", nil, "commands; the guide shows each one's format, * marks what's required"),
                 ("#room message", nil, "send to a room you're in and switch to it"),
                 (":name", nil, "emoji, e.g. :smile"),
                 ("**bold** *italic* `code`", nil, "markdown, also ~~strike~~ and [text](link)"),
                 ("@name", nil, "mention someone: they hear a sound. Tab completes names"),
                 ("name#0412", nil, "a name and its tag, for when two people share a name: works in @mentions and wherever a username goes. Settings > Profile shows yours"),
                 ("drag a message", nil, "move the overlay; right-click it to lock it in place")]),
     ("Symbols", [("2", .green, "in the chat bar: people online now, or in your room when you're in a private one. A lock beside it: that room is end-to-end encrypted"),
                  ("menu bar icon", .red, "not connected"),
                  ("menu bar icon", .yellow, "the network blocks Macs from reaching each other, so Psst uses Wi-Fi directly between Macs about 30 m apart. Macs further away connect through up to 2 Macs in between"),
                  ("menu bar icon", .blue, "an update is available"),
                  ("★", nil, "a friend"),
                  ("◆", nil, "the creator of the room you're in"),
                  ("name", .green, "online"),
                  ("name", .red, "do not disturb")])]
}

struct HelpView: View {
    let focus: String?, shortcut: String
    @State private var query = ""
    @State private var opened: Set<String> = []  // every section starts folded

    func matches(_ parts: String...) -> Bool { query.isEmpty || parts.contains { $0.localizedCaseInsensitiveContains(query) } }
    func isOpen(_ title: String) -> Bool { !query.isEmpty || opened.contains(title) }  // searching opens everything
    func setOpen(_ title: String, _ open: Bool) { if open { opened.insert(title) } else { opened.remove(title) } }

    /// A section title that folds the section away, and back.
    func header(_ title: String) -> some View {
        Button { setOpen(title, !isOpen(title)) } label: {
            HStack(spacing: 6) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.secondary)
                    .rotationEffect(.degrees(isOpen(title) ? 90 : 0))
                Text(title).font(.title3.weight(.semibold))
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!query.isEmpty)
    }

    var body: some View {
        VStack(spacing: 0) {
            TextField("Search", text: $query)
                .textFieldStyle(.roundedBorder)
                .padding(12)
            Divider()
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        ForEach(helpGroups, id: \.title) { group in
                            let shown = group.names.filter { n in
                                let c = commands.first { $0.name == n }!
                                return matches(usage(c), c.help, commandDetails[n]?.text ?? "", shortcuts(n).joined(separator: " "))
                            }
                            if !shown.isEmpty {
                                VStack(alignment: .leading, spacing: 8) {
                                    header(group.title)
                                    if isOpen(group.title) {
                                        ForEach(shown, id: \.self) { CommandCard(name: $0, focused: $0 == focus).id($0) }
                                    }
                                }
                            }
                        }
                        ForEach(helpTopics(shortcut: shortcut), id: \.title) { topic in
                            let rows = topic.rows.filter { matches($0.key, $0.text) }
                            if !rows.isEmpty {
                                VStack(alignment: .leading, spacing: 8) {
                                    header(topic.title)
                                    if isOpen(topic.title) {
                                    VStack(alignment: .leading, spacing: 6) {
                                        ForEach(rows.indices, id: \.self) { i in
                                            HStack(alignment: .firstTextBaseline, spacing: 10) {
                                                HStack(spacing: 4) {
                                                    if let dot = rows[i].dot { Text("●").foregroundColor(dot) }
                                                    Text(rows[i].key).font(.system(.body, design: .monospaced))
                                                }
                                                .frame(width: 170, alignment: .leading)
                                                Text(rows[i].text).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                                            }
                                        }
                                    }
                                    .padding(12)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
                                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color(nsColor: .separatorColor)))
                                    }
                                }
                            }
                        }
                    }
                    .padding(16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                }
                .onAppear {  // /help room: its section opens, and it scrolls there
                    guard let focus, let group = helpGroups.first(where: { $0.names.contains(focus) }) else { return }
                    setOpen(group.title, true)
                    DispatchQueue.main.async { proxy.scrollTo(focus, anchor: .top) }
                }
            }
        }
        .frame(minWidth: 480, minHeight: 360)
    }
}

struct CommandCard: View {
    let name: String, focused: Bool

    var body: some View {
        let c = commands.first { $0.name == name }!, d = commandDetails[name]
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(usage(c)).font(.system(.body, design: .monospaced).weight(.semibold))
                Spacer()
                if !shortcuts(name).isEmpty {
                    Text(shortcuts(name).joined(separator: "  ")).font(.system(.callout, design: .monospaced)).foregroundColor(.secondary)
                }
            }
            Text(LocalizedStringKey(d?.text ?? c.help)).fixedSize(horizontal: false, vertical: true)
            ForEach(d?.examples ?? [], id: \.self) { Text($0).font(.system(.callout, design: .monospaced)).foregroundColor(.secondary) }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(focused ? Color.accentColor : Color(nsColor: .separatorColor), lineWidth: focused ? 2 : 1))
    }
}

extension App {
    /// Opens the help page, scrolled to `command` (a full name such as /room) if given.
    func showHelp(_ command: String? = nil) {
        if helpWindow == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 600, height: 680), styleMask: [.titled, .closable, .resizable, .miniaturizable],
                             backing: .buffered, defer: false)
            w.isReleasedWhenClosed = false
            w.title = "Psst Help"
            w.center()
            helpWindow = w
        }
        helpWindow!.contentView = NSHostingView(rootView: HelpView(focus: command, shortcut: shortcut))
        NSApp.activate(ignoringOtherApps: true)
        helpWindow!.makeKeyAndOrderFront(nil)
    }

    @objc func openHelp() { showHelp() }
}
