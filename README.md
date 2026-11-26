# Psst

Chat overlay for Macs on the same local network. No accounts, no central server.

## Install

1. Download `Psst.zip` from [Releases](../../releases/latest) and unzip it.
2. Move `Psst.app` to a folder in your home folder, such as `~/Applications`.
3. On first launch, right-click `Psst.app` and choose **Open** (the app is not notarized), then **allow local network access**. If it does not open, System Settings > Privacy & Security > Open Anyways (scroll down).
4. Choose a username. It can be changed every two weeks. Your Mac also picks a permanent 4-digit tag, so two people named ana show as `ana#0412` and `ana#7731`.

Psst updates itself daily by default. The interval can be changed or updates turned off in Settings. Psst checks on launch; Settings > General shows when an update is available, with **Check Now** and **Update Now**.

## Usage

| Key | Action |
|---|---|
| ⌥ Space | Open the chat bar (configurable) |
| Enter | Send |
| Shift + Enter | New line |
| Tab | Accept suggestion |
| Esc | Go back or close |
| ⌘Q | Quit |

- Type `/` for commands. `/help` opens a help page with every command explained. Full list: [commands.md](commands.md).
- Macs running Psst find each other automatically, over the network or directly over Wi-Fi. Macs out of range connect through nearby ones. Some networks hide Macs from each other but still let them connect: there, once one Mac is in, the others learn each other's network addresses and connect across the whole network.
- A red dot on the menu bar icon means Psst isn't connected. A yellow dot means the network (or a VPN) blocks Macs from reaching each other, so Psst uses Wi-Fi directly between Macs about 30 m apart. Macs further away connect through up to 2 Macs in between. A blue dot means an update is available.
- The chat bar shows how many people are online (● 2), or how many are in your private room, with a lock for its end-to-end encryption. In the menu, a red dot marks do not disturb, and ◆ marks the creator of the room you're in.
- One Mac hosts. If it quits, the next one takes over with rooms and recent messages intact.
- Messages fade after a few seconds. `/history on` keeps them.
- Swearing and NSFW words are hidden in messages by default and not allowed in usernames.
- Typing indicators, mention sounds, pings, which side messages appear on and their size can be changed in Settings.
- When two people share a name, add the tag: `@ana#0412`, `/ping ana#0412`.
- `/messages off` stops new messages while you stay online. `/friend rename` gives a friend a name only you see.
- Drag a message to move the overlay. Right-click to lock its position.

## Privacy

- Everything Psst sends between Macs is encrypted: someone watching the network sees which Macs talk, not what they say. Someone who sits between two Macs and passes their traffic on could still read it.
- Private rooms are also end-to-end encrypted, so not even the host can read them. Public chat is readable by the host and everyone in it.
- Keys are remembered on first contact. If a user's key changes, Psst warns you and stops encrypting to them until you compare codes with `/key [username]` and confirm with `/trust [username]`.
- Room passwords are hashed before sending, but the host can replay the hash.
- Profile pictures are visible to everyone using Psst.
- Once a minute, the host shares its own network address and those of the next two Macs in line to host (never invisible people's), so Macs can reconnect on networks that hide them from each other. A new address waits a random 1 to 10 minutes first, so it can't be matched to whoever just joined. Psst remembers these for 3 days.
- The host sees who is online, room membership and message timing, but not private-room content. The next two Macs in line to host keep a copy.

## Build

```sh
./build.sh                                   # universal Psst.app, macOS 12+
./Psst.app/Contents/MacOS/Psst --selftest    # host logic, network, markdown, update signing
./release.sh 1.5.0                           # signed GitHub release; installed copies update themselves
```

Releases are signed with an Ed25519 key at `~/.config/psst/update.key`. Installed copies reject updates without a valid signature. Back up the key: without it, no further updates can be released.
