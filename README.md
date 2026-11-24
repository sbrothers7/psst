# Psst

A tiny chat overlay for Macs on the same network. Messages appear in a corner of the screen and fade away. Nothing is saved.

## Install

1. Download `Psst.zip` from [Releases](../../releases/latest) and unzip it.
2. Move `Psst.app` into a folder inside your home folder, such as `~/Applications`.
3. The first time, right-click `Psst.app` and choose **Open**. Apple will block Psst as it is not from the App Store. Allow local network access when macOS asks.
4. Pick a username (can be change biweekly).

Psst checks for updates every few hours and installs them by itself.

## Use

- **⌥ + Space** opens the chat bar. **Enter** sends, **Esc** closes, **⌘Q** or `/quit` quits.
- One person types `/host`. Everyone else connects automatically, over the network. If the network blocked or unavailable, Psst will connect directly over Wi-Fi (like AirDrop).
- Type `/` to see every command, or `:name` for emoji (`:fire:` 🔥). Messages support `**bold**`, `*italic*`, `` `code` `` and `~~strike~~`.
- `/room`, `/invite`, `/join` and `/leave` handle private rooms. A room closes when the room host user leaves or quits.
- Drag the bubbles to move them. Right-click a bubble to lock it in place.
- `/settings` holds your name, visibility, who can invite you, and fade time. `/setup` shows the welcome again.

## Privacy

- **Private rooms are end-to-end encrypted.**
- **Public chat is not encrypted.** Anyone in it, or watching the network, can read it.
- **Keys:** Psst remembers each person's key the first time it sees them. If someone's key changes (a new Mac, or someone in the middle), you get a warning and they can't read your private-room messages until you check. Run `/key name` on both Macs, compare the codes in person, then `/trust name`.
- **What the host still sees:** who is online, who is in which room, and when people send messages.

## Build

```sh
./build.sh                                   # universal Psst.app, macOS 12+
./Psst.app/Contents/MacOS/Psst --selftest    # host logic, network, markdown, update signing
./release.sh 1.1                             # signed GitHub release; every copy updates itself
```

Releases are signed with an Ed25519 key kept at `~/.config/psst/update.key` on the release Mac. Installed copies refuse any update without a valid signature. If that key is lost, no further updates can be shipped, so back it up.
