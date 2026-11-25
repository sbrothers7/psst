# Psst

Chat overlay for Macs on the same local network. No accounts, no central server.

## Install

1. Download `Psst.zip` from [Releases](../../releases/latest) and unzip it.
2. Move `Psst.app` to a folder in your home folder, such as `~/Applications`.
3. On first launch, right-click `Psst.app` and choose **Open** (the app is not notarized), then **allow local network access**. If it does not open, System Settings > Privacy & Security > Open Anyways (scroll down).
4. Choose a username. It can be changed every two weeks.

Psst updates itself daily by default. The interval can be changed or updates turned off in Settings.

## Usage

| Key | Action |
|---|---|
| ⌥ Space | Open the chat bar (configurable) |
| Enter | Send |
| Shift + Enter | New line |
| Tab | Accept suggestion |
| Esc | Go back or close |
| ⌘Q | Quit |

- Type `/` for commands. Full list: [commands.md](commands.md).
- Macs running Psst find each other automatically, over the network or directly over Wi-Fi. Macs out of range connect through nearby ones.
- One Mac hosts. If it quits, the next one takes over with rooms and recent messages intact.
- Messages fade after a few seconds. `/history on` keeps them.
- Drag a message to move the overlay. Right-click to lock its position.

## Privacy

- Private rooms are end-to-end encrypted. Public chat is not.
- Keys are remembered on first contact. If a user's key changes, Psst warns you and stops encrypting to them until you compare codes with `/key [username]` and confirm with `/trust [username]`.
- Room passwords are hashed before sending, but anyone on the network can replay the hash.
- Profile pictures are visible to everyone on the network.
- The host sees who is online, room membership and message timing, but not private-room content. The next two Macs in line to host keep a copy.

## Build

```sh
./build.sh                                   # universal Psst.app, macOS 12+
./Psst.app/Contents/MacOS/Psst --selftest    # host logic, network, markdown, update signing
./release.sh 1.5.0                           # signed GitHub release; installed copies update themselves
```

Releases are signed with an Ed25519 key at `~/.config/psst/update.key`. Installed copies reject updates without a valid signature. Back up the key: without it, no further updates can be released.
