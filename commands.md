# Commands

`*` marks a required parameter. Commands that list items open a menu when sent without arguments: ↑↓ to move, Enter to select, Esc to go back.

## General

| Command | Description |
|---|---|
| `/status [username]` | List online users, or check one |
| `/friend [list\|add\|remove]* [username]` | Manage friends |
| `/block [username]` | Block or unblock a user. No argument lists blocked users |
| `/nick [nickname]` | Set your nickname in the current room. No argument clears it |
| `/history [on\|off]` | Keep messages with scrollback, or let them fade. No argument toggles |
| `/key [username]` | Show a key code for verification. No argument shows yours |
| `/trust [username]*` | Accept a user's new key |
| `/settings` | Open settings |
| `/quit` | Quit Psst |

## Rooms

| Command | Description |
|---|---|
| `/room` | Room menu |
| `/room create [room name]* [type] [desc]` | Create a room. Type defaults to 0 |
| `/room [room name] set name [new]*` | Rename a room |
| `/room [room name] set desc [new]*` | Set the description |
| `/room [room name] set password [new]*` | Set the password |
| `/room [room name] set type [0–3]*` | Set the access type |
| `/room member list` | List members |
| `/room member kick [username]*` | Remove a member (creator only) |
| `/room member ban [username]*` | Remove a member and block rejoining. Repeat to unban (creator only) |
| `/browse [room name]` | List rooms on the network |
| `/join [room name] [password]` | Switch to or join a room. No argument returns to public |
| `/request [room name]*` | Request to join a room (once per minute) |
| `/accept [username\|all]` | Accept join requests. No argument accepts the latest |
| `/invite [username]*` | Invite a user to the current room |
| `/leave` | Leave the current room. A room closes when its creator leaves |

In `set` commands, `[room name]` defaults to the current room; `current` also refers to it. Reserved names: `public`, `current`, `create`, `set`, `member`.

### Room types

| Type | Access |
|---|---|
| 0 | Invite only (default) |
| 1 | Password only |
| 2 | Invite or password |
| 3 | Open |

Creating a type 1 or 2 room prompts for a password. Setting a password on a type 0 or 3 room prompts to switch to type 1 or 2.

## Input

- `#[room name] message` sends to that room.
- `:name` inserts an emoji.
- Markdown: `**bold**`, `*italic*`, `` `code` ``, `~~strike~~`. Markers close automatically.
- Room descriptions are quoted automatically.
