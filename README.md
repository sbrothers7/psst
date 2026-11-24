# Psst

A tiny LAN chat overlay for Macs.

## Install

1. Download `Psst.zip` from [Releases](../../releases/latest) and unzip it.
2. Move `Psst.app` into a folder inside your home folder, such as `~/Applications`.
3. The first time, right-click `Psst.app` and choose **Open**. Apple will block Psst as it is not from the App Store. Allow local network access when macOS asks.
4. Pick a username (can be change biweekly).

Psst checks for updates every hour and when your Mac wakes, and installs them by itself. Setup offers to open Psst at login (macOS 13+); change it any time in Settings.

## Use

- **⌥ + Space** opens the chat bar (change it in Settings). **Enter** sends, **Esc** closes, **⌘Q** or `/quit` quits.
- No setup: Psst finds other Macs running it and connects on its own, over the network or, if the network blocks it, directly over Wi-Fi (like AirDrop). Macs out of Wi-Fi range of the host connect through Macs in between.
- Every Mac can host; everyone shares the one that has been running longest. If it leaves, the next one takes over with the same rooms and recent messages.
- Type `/` to see every command, or `:name` for emoji (`:fire:` 🔥). Messages support `**bold**`, `*italic*`, `` `code` `` and `~~strike~~`.
- `/room <name>` makes a private room; `/room` alone lists who is in it. `/invite`, `/join` and `/leave` do the rest. A room closes when the room host user leaves or quits.
- `/rooms` lists every room on the network. Pick one to ask to join, or `/request <room name>`. Members see the request and let people in with `/accept` (latest), `/accept <username>` or `/accept all`. One request a minute.
- You can be in several rooms at once. Use `/join <room name>` to switch. starting a message with `#<room name>` sends it in the room specified.
- `/nick <nickname>` sets your name in the current private room only. Public chat always shows usernames.
- `/status` and `/friend list` show online status. Use ↑↓ and Enter to pick someone to manage.
- Drag the bubbles to move them. Right-click a bubble to lock it in place.
- `/settings` opens settings.

## Privacy

- **Private rooms are end-to-end encrypted.**
- **Public chat is not encrypted.** Anyone in it, or watching the network, can read it.
- **Keys:** Psst remembers each person's key the first time it sees them. If someone's key changes (a new Mac, or someone in the middle), you get a warning and they can't read your private-room messages until you check. Run `/key <username>` on both Macs, compare the codes in person, then `/trust <username>`.
- The **host** can still see who is online, who is in which room, and when people send messages. The next two Macs in line to host keep a copy of the same, plus recent messages (private-room ones stay encrypted), so they can take over.

## Build

```sh
./build.sh                                   # universal Psst.app, macOS 12+
./Psst.app/Contents/MacOS/Psst --selftest    # host logic, network, markdown, update signing
./release.sh 1.1                             # signed GitHub release; every copy updates itself
```

Releases are signed with an Ed25519 key kept at `~/.config/psst/update.key` on the release Mac. Installed copies refuse any update without a valid signature. If that key is lost, no further updates can be shipped; backing it up is recommended.
