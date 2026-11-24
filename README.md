# Psst

A tiny chat overlay for Macs on the same network. Messages appear in a corner of the screen and fade away. Nothing is saved.

## Install

1. Download `Psst.zip` from [Releases](../../releases/latest) and unzip it.
2. Move `Psst.app` into a folder inside your home folder, such as `~/Applications`. School accounts often can't write to the main Applications folder, and then Psst can't update itself.
3. The first time, right-click `Psst.app` and choose **Open**, because it isn't from the App Store. Allow local network access when macOS asks.
4. Pick the username classmates will see. You can change it once every 2 weeks.

Psst checks for updates every few hours and installs them by itself.

## Use

- **⌥Space** opens the chat bar. **Enter** sends, **Esc** closes, **⌘Q** or `/quit` quits.
- One person types `/host`. Everyone else on the network connects automatically.
- Type `/` to see every command, or `:name` for emoji (`:fire:` 🔥). Messages support `**bold**`, `*italic*`, `` `code` `` and `~~strike~~`.
- `/room`, `/invite`, `/join` and `/leave` handle private rooms. `/friend list|add|remove` and `/block` manage people.
- Drag the bubbles to move them. Right-click a bubble to lock it in place.
- `/settings` holds your name, visibility, who can invite you, and fade time. `/setup` shows the welcome again.

Messages travel unencrypted on the local network, so don't send anything private.

## Build

```sh
./build.sh                                   # universal Psst.app, macOS 12+
./Psst.app/Contents/MacOS/Psst --selftest    # host logic, network, markdown, update signing
./release.sh 1.1                             # signed GitHub release; every copy updates itself
```

Releases are signed with an Ed25519 key kept at `~/.config/psst/update.key` on the release Mac. Installed copies refuse any update without a valid signature. If that key is lost, no further updates can be shipped, so back it up.
