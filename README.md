# Discord Voice State Widget for Omarchy

A lightweight vibecoded Discord voice status widget for [Omarchy](https://omarchy.org/).

## Why

The Windows version of Discord has much more useful tray icon: it shows when you are speaking, muted or deafened. This widget returns this in Omarchy.

<img width="213" height="28" alt="image" src="https://github.com/user-attachments/assets/c6d2f84c-8276-4d02-8690-8597e6762bea" />

## Features

- **Live Voice Status:** Displays real-time voice channel states: (connected, speaking, muted, deafened) just like Discord should have done.
- **Auto-Hide:** Completely collapses and takes zero space on the bar when you are not in an active voice channel or when Discord is closed.
- **Quick Controls:**
  - **Left Click:** Toggle Mute (or Undeafen & Unmute if deafened, matching native Discord behavior).
  - **Right Click:** Toggle Deafen.
- **Global Keybinding Support:** Supports instantaneous toggling via standard POSIX signals, bypassing Wayland global hotkey limitations in Discord.
- **Multi-Monitor Optimized:** Built using Omarchy's singleton `service` architecture so only a single lightweight background daemon runs across multiple displays.

## Known Quirks

- If you join a voice channel immediately after launching Discord, the icon may take a few seconds to appear (the bridge retries connecting to Discord every 5 seconds when Discord isn't running).
- If you transfer or reconnect to a voice channel from another device, the widget may still show you as connected until you explicitly disconnect.

## Installation & Setup

1. In the Omarchy menu, select `Add Plugin` and enter:
   ```
   https://github.com/Matredit/omarchy-discord-voice-widget.git
   ```
   Or follow the [Omarchy manual](https://omarchy.org/manual/shell-plugins/#adding-a-plugin-from-git).
2. When the plugin starts, Discord will show an authorization popup for **Discord StreamKit Overlay**. Click **Authorize**.
3. Once authorized, the widget will automatically appear on your bar whenever you are in an active voice channel.

## Global Hotkeys

Default Discord hotkeys might not work on Wayland, so you can bind mute/deafen hotkeys directly in your `~/.config/hypr/bindings.lua`:

```lua
-- Toggle Discord Mute
hl.unbind("ALT + Z")
o.bind("ALT + Z", "Discord toggle mute", "python3 ~/.config/omarchy/plugins/opoii.discord/discord_bridge.py --toggle-mute")

-- Toggle Discord Deafen
hl.unbind("SUPER + ALT + Z")
o.bind("SUPER + ALT + Z", "Discord toggle deafen", "python3 ~/.config/omarchy/plugins/opoii.discord/discord_bridge.py --toggle-deafen")
```

## Removal

1. In the Omarchy menu, select `Remove Plugin` and choose `opoii.discord`.
2. Optional cleanup:
   - **Cached token:** Delete `~/.cache/omarchy/discord_plugin/` (`rm -rf ~/.cache/omarchy/discord_plugin`).
   - **Discord authorization:** In Discord, go to **User Settings** -> **Authorized Apps** and click **Deauthorize** on **Discord StreamKit Overlay**.
   - **Keybindings:** Remove any custom hotkey lines added to `~/.config/hypr/bindings.lua`.

---

## Technical Details (AI summary)

### Architecture

The plugin consists of three components:

1. **`Service.qml` (Singleton Service):**
   Manages the lifecycle of `discord_bridge.py` as a single background process shared across all monitors. It reads JSON status lines from stdout (`tray`, `tray-connected`, `tray-muted`, `tray-deafened`, `tray-speaking`) and forwards click commands to the daemon via stdin (`toggle_mute\n`, `toggle_deafen\n`).

2. **`Widget.qml` (Bar Widget):**
   Bar icon component bound to `Service.qml`. It displays the current voice state icon, hides when disconnected, and handles mouse clicks directly through the singleton service without executing shell commands.

3. **`discord_bridge.py` (Python IPC Daemon):**
   Async daemon that communicates with Discord's local RPC socket, manages OAuth authorization, subscribes to voice events, and emits state updates.

### Local IPC & Protocol Security

- **Socket Discovery & Identity:** Discovers candidate sockets (`discord-ipc-0` through `9`) under verified user directories (`XDG_RUNTIME_DIR`, Flatpak, Snap). Unsafe paths such as raw `/tmp` are rejected. Sockets and parent directory chains are verified via descriptor-relative traversal with `O_NOFOLLOW` ensuring user ownership, mode restrictions, and no symlinks.
- **Peer Verification:** Connected sockets are verified immediately via `SO_PEERCRED` (`peer_uid == getuid()`, `peer_pid > 0`) before transmitting any data.
- **Bounded Frame Parsing:** Enforces a 64 KiB frame ceiling (`MAX_FRAME_SIZE`) before reading payloads to prevent unbounded memory allocation. Header and payload reads enforce explicit deadlines to prevent hangs on stalled sockets. Frame opcodes and JSON schemas are strictly validated.
- **Handshake Authentication:** The daemon sends `OP_HANDSHAKE` and requires Discord to return an authentic `READY` dispatch containing Discord API/CDN configuration before any credentials are sent. Fake or unverified sockets are rejected immediately.
- **Heartbeat & Deadlines:** All connection phases have explicit timeouts (connect 2.0s, handshake 5.0s, initialization 15.0s, per-command 10.0s). The read loop uses a 30s idle ping interval with a 5s pong deadline to detect half-open or unresponsive sockets.

### OAuth Token Persistence & Exchange

- **Scopes:** Requests `rpc.voice.read` and `rpc.voice.write` using Discord's official first-party StreamKit client ID (`207646673902501888`), prompting the user via Discord's native authorization dialog.
- **Code Exchange:** Exchanged with `https://streamkit.discord.com/overlay/token` via HTTPS POST. The code input is length-bounded and character-restricted. Redirects are restricted to HTTPS on `streamkit.discord.com` (max 3 hops), responses have a 32 KiB ceiling, and an overall 10s deadline is enforced.
- **Secure Persistence:** Token is cached in `~/.cache/omarchy/discord_plugin/token.json`. Directory chains are traversed and verified with `O_NOFOLLOW` and mode 0700. Writes use exclusive random temporary files (`O_CREAT | O_EXCL | O_NOFOLLOW`), mode 0600 permissions, `fsync`, and atomic descriptor-relative replacement. Reads enforce mode 0600, user ownership, and an 8 KiB size ceiling.

### Control Path & Hotkey Signaling

- **In-Bar Controls:** Handled via stdin pipe between `Service.qml` and `discord_bridge.py`, requiring no PID files or signal delivery.
- **External CLI (`--toggle-mute`, `--toggle-deafen`):** Used for window manager keybindings. The running daemon writes a PID record to the verified runtime directory. Before sending `SIGUSR1`/`SIGUSR2`, the CLI verifies:
  1. The target process UID in `/proc/[pid]/status` matches current user.
  2. The target start time in `/proc/[pid]/stat` matches the recorded start time (preventing PID reuse attacks).
  3. The target process command line in `/proc/[pid]/cmdline` matches `discord_bridge.py`.
  4. The target binary in `/proc/[pid]/exe` resolves to Python.
     Stale PID files from terminated processes are removed automatically.
