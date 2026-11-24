# Psst

A tiny LAN chat overlay for Macs.

## Install

1. Download `Psst.zip` from [Releases](../../releases/latest) and unzip it.
2. Move `Psst.app` into a folder inside your home folder, such as `~/Applications`.
3. The first time, right-click `Psst.app` and choose **Open**. Apple will block Psst as it is not from the App Store. Allow local network access when macOS asks.
4. Pick a username (can be change biweekly).

Psst checks for updates once a day and installs them by itself. In Settings you can check every hour, 6 hours, 12 hours or week instead, or turn automatic updates off. Setup offers to open Psst at login (macOS 13+); change it any time in Settings.

## Use

- **⌥ + Space** opens the chat bar (change it in Settings). **Enter** sends, **Shift + Enter** starts a new line (the bar grows to fit), **Tab** completes what the guide suggests, **Esc** closes, **⌘Q** or `/quit` quits.
- No setup: Psst finds other Macs running it and connects on its own, over the network or, if the network blocks it, directly over Wi-Fi (like AirDrop). Macs out of Wi-Fi range of the host connect through Macs in between.
- Every Mac can host; everyone shares the one that has been running longest. If it leaves, the next one takes over with the same rooms and recent messages.
- Type `/` to see every command, or `:name` for emoji (`:fire:` 🔥). Messages support `**bold**`, `*italic*`, `` `code` `` and `~~strike~~`.
- `/room` does everything about rooms; its guide changes as you type and says what Enter will do. `/room` alone opens it as a menu. A red `*` marks what a command needs.
  - `/room create [room name]* [desc] [type]` makes a private room. The description and type are optional; a last word 0–3 is the type: `/room create chess after school 2`.
  - Types say who can get in: **0** invite only (the default), **1** password only, **2** invite or password, **3** open access. Making a type 1 or 2 room asks for its password next.
  - `/room [room name] set [name|desc|password|type]* [new]*` changes a room you're in: `/room chess set name club`, `/room set type 3`. Leave out the room name, or write `current`, for the room you're in. Setting a password on a type 0 or 3 room asks whether to switch to 1 or 2, since those types don't use it.
  - `/room members` lists who is in the room. `public`, `current`, `create`, `set` and `members` can't be room names.
- `/invite`, `/join` and `/leave` do the rest. A room closes when the room host user leaves or quits.
- `/browse` lists every room on the network with its type. Pick one to join, type its password, or ask to join (`/request [room name]`), depending on the type. Members see the request and let people in with `/accept` (latest), `/accept [username]` or `/accept all`. One request a minute.
- You can be in several rooms at once. Use `/join [room name]` to switch. starting a message with `#[room name]` sends it in the room specified.
- `/nick [nickname]` sets your name in the current private room only. Public chat always shows usernames.
- `/status`, `/friend list`, `/browse` and other lists open as a menu. Use ↑↓ and Enter to pick someone, then what to do (add or remove friend, invite, block). The menu stays open until **Esc**, which goes back a step at a time.
- Your messages sit on the right; others' show their name, and their picture if they set one in Settings (an image, or letters from their username).
- Messages fade after a few seconds. `/history on` keeps them so you can scroll back (it also fetches what the host still has); `/history off` lets them fade again.
- Drag the bubbles to move them. Right-click a bubble to lock it in place.
- `/settings` opens settings.

## Privacy

- **Private rooms are end-to-end encrypted.**
- **Public chat is not encrypted.** Anyone in it, or watching the network, can read it.
- **Keys:** Psst remembers each person's key the first time it sees them. If someone's key changes (a new Mac, or someone in the middle), you get a warning and they can't read your private-room messages until you check. Run `/key [username]` on both Macs, compare the codes in person, then `/trust [username]`.
- **Room passwords** leave your Mac hashed, never as typed. Anyone watching the network could still reuse that hash to get in, so a password keeps out classmates, not eavesdroppers.
- A **profile picture** goes to everyone on the network, unencrypted, like public chat. Invisible people's pictures aren't sent.
- The **host** can still see who is online, who is in which room, and when people send messages. The next two Macs in line to host keep a copy of the same, plus recent messages (private-room ones stay encrypted), so they can take over.

## Build

```sh
./build.sh                                   # universal Psst.app, macOS 12+
./Psst.app/Contents/MacOS/Psst --selftest    # host logic, network, markdown, update signing
./release.sh 1.1                             # signed GitHub release; every copy updates itself
```

Releases are signed with an Ed25519 key kept at `~/.config/psst/update.key` on the release Mac. Installed copies refuse any update without a valid signature. If that key is lost, no further updates can be shipped; backing it up is recommended.
