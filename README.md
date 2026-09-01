# Discord Voice State Widget for Omarchy

A lightweight, responsive Discord voice status widget for [Omarchy](https://omarchy.org/).

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

## How It Works

1. **Python IPC Daemon (`discord_bridge.py`):**
   Connects directly to Discord's local UNIX IPC socket (`discord-ipc-0`) via RPC / OAuth. It listens for voice events (`VOICE_CHANNEL_SELECT`, `VOICE_STATE_UPDATE`, `SPEAKING_START`/`STOP`, `VOICE_SETTINGS_UPDATE`) and emits state updates over `stdout`.
2. **Omarchy Service (`Service.qml`):**
   A singleton background service that manages the lifecycle of the Python daemon, parsing state streams and exposing properties to the shell.
3. **Bar Widget (`Widget.qml`):**
   The frontend UI that dynamically loads status icons, collapses when inactive, and executes low-latency signals upon interaction.
4. **Low-Latency Signaling:**
   The daemon writes its PID to `/tmp/opoii_discord_bridge_$(id -u).pid`. Interactions trigger `SIGUSR1` (Mute) and `SIGUSR2` (Deafen) directly to the process, executing state changes in under 1ms.

### Authentication & Permissions

On first launch, Discord will show a one-time authorization prompt for **"Discord StreamKit Overlay"**:

- Discord's local RPC requires OAuth scopes (`rpc.voice.read`, `rpc.voice.write`) to inspect voice status and toggle mute/deafen.
- Using Discord's official first-party StreamKit client ID allows the plugin to work out-of-the-box without requiring users to create and configure their own Discord Developer App.
- The granted token is cached locally in `~/.cache/omarchy/discord_plugin/token.json` so you only need to authorize it once.

The icon may show a few seconds later if you just launched discord and joined a channel straight away.

## Installation

Follow the [manual](https://omarchy.org/manual/shell-plugins/#adding-a-plugin-from-git) or  
Use `Add Plugin` in the Omarchy menu and paste
`https://github.com/Matredit/omarchy-discord-voice-widget.git`

## Removal

Use `Remove Plugin` in the Omarchy menu and choose `opoii.discord`

## Global Hotkeys (Hyprland)

Default Discord hotkeys might not work on Wayland, so you can bind mute/deafen hotkeys directly in your `~/.config/hypr/bindings.lua`:

```lua
-- Toggle Discord Mute
hl.unbind("ALT + Z")
o.bind("ALT + Z", "Discord toggle mute", "kill -USR1 $(cat /tmp/opoii_discord_bridge_$(id -u).pid)")

-- Toggle Discord Deafen
hl.unbind("SUPER + ALT + Z")
o.bind("SUPER + ALT + Z", "Discord toggle deafen", "kill -USR2 $(cat /tmp/opoii_discord_bridge_$(id -u).pid)")
```
