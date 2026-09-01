#!/usr/bin/env python3
import asyncio
import json
import os
import struct
import sys
import urllib.request
import ctypes
import signal

# Ensure the process dies if the parent (omarchy-shell) dies
try:
    libc = ctypes.CDLL("libc.so.6")
    libc.prctl(1, signal.SIGTERM)
except Exception:
    pass


DEFAULT_CLIENT_ID = "207646673902501888"
OAUTH_SCOPES = ["rpc", "rpc.voice.read", "rpc.voice.write"]
TOKEN_EXCHANGE_URL = "https://streamkit.discord.com/overlay/token"
OP_HANDSHAKE = 0
OP_FRAME = 1
OP_CLOSE = 2
OP_PING = 3
OP_PONG = 4

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, flush=True)

class DiscordIPC:
    def __init__(self):
        self.reader = None
        self.writer = None
        self._nonce = 0

    @staticmethod
    def _candidate_paths():
        paths = []
        env_dirs = []
        if xdg := os.environ.get("XDG_RUNTIME_DIR"):
            env_dirs.append(xdg)
            flatpak = os.path.join(xdg, "app", "com.discordapp.Discord")
            if os.path.isdir(flatpak): env_dirs.append(flatpak)
        if snap := os.environ.get("SNAP_USER_DATA"):
            env_dirs.append(os.path.join(snap, ".config"))
        for var in ("TMPDIR", "TMP", "TEMP"):
            if d := os.environ.get(var): env_dirs.append(d)
        env_dirs.append("/tmp")
        for d in env_dirs:
            for i in range(10):
                paths.append(os.path.join(d, f"discord-ipc-{i}"))
        return paths

    async def connect(self):
        for path in self._candidate_paths():
            if not os.path.exists(path): continue
            try:
                r, w = await asyncio.open_unix_connection(path)
                self.reader, self.writer = r, w
                return True
            except OSError:
                continue
        return False

    def close(self):
        if self.writer:
            try: self.writer.close()
            except Exception: pass
            self.writer = None
            self.reader = None

    @property
    def connected(self):
        return self.writer is not None and not self.writer.is_closing()

    async def send_frame(self, opcode, payload):
        data = json.dumps(payload).encode("utf-8")
        header = struct.pack("<II", opcode, len(data))
        self.writer.write(header + data)
        await self.writer.drain()

    async def recv_frame(self):
        header = await self.reader.readexactly(8)
        opcode, length = struct.unpack("<II", header)
        data = await self.reader.readexactly(length)
        payload = json.loads(data.decode("utf-8"))
        return opcode, payload

    def _next_nonce(self):
        self._nonce += 1
        return str(self._nonce)

    async def handshake(self, client_id):
        await self.send_frame(OP_HANDSHAKE, {"v": 1, "client_id": client_id})
        op, data = await self.recv_frame()
        if op == OP_CLOSE: raise ConnectionError(f"Closed: {data}")
        return data

    async def authorize(self, client_id, scopes):
        nonce = self._next_nonce()
        await self.send_frame(OP_FRAME, {
            "cmd": "AUTHORIZE", "args": {"client_id": client_id, "scopes": scopes, "prompt": "none"}, "nonce": nonce
        })
        return nonce

    async def authenticate(self, access_token):
        nonce = self._next_nonce()
        await self.send_frame(OP_FRAME, {
            "cmd": "AUTHENTICATE", "args": {"access_token": access_token}, "nonce": nonce
        })
        return nonce

    async def subscribe(self, evt, args=None):
        nonce = self._next_nonce()
        payload = {"cmd": "SUBSCRIBE", "evt": evt, "nonce": nonce}
        if args: payload["args"] = args
        await self.send_frame(OP_FRAME, payload)
        return nonce

    async def unsubscribe(self, evt, args=None):
        nonce = self._next_nonce()
        payload = {"cmd": "UNSUBSCRIBE", "evt": evt, "nonce": nonce}
        if args: payload["args"] = args
        await self.send_frame(OP_FRAME, payload)
        return nonce

class TokenManager:
    def __init__(self):
        xdg_cache = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
        cache_dir = os.path.join(xdg_cache, "omarchy", "discord_plugin")
        self._cache_path = os.path.join(cache_dir, "token.json")
        self.access_token = None

    def load(self):
        try:
            with open(self._cache_path) as f:
                self.access_token = json.load(f).get("access_token")
                return self.access_token
        except Exception:
            return None

    def save(self, token):
        self.access_token = token
        os.makedirs(os.path.dirname(self._cache_path), exist_ok=True)
        fd = os.open(self._cache_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"access_token": token}, f)

    def clear(self):
        self.access_token = None
        try: os.unlink(self._cache_path)
        except Exception: pass

    @staticmethod
    def exchange_code(code):
        body = json.dumps({"code": code}).encode("utf-8")
        req = urllib.request.Request(
            TOKEN_EXCHANGE_URL, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "OmarchyDiscordWidget/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))["access_token"]


class DiscordBridge:
    def __init__(self):
        self.discord = DiscordIPC()
        self.tokens = TokenManager()
        self.authenticated = False
        self._pending = {}
        self.current_user_id = None
        self.current_channel_id = None
        
        # State tracking
        self.settings = {"mute": False, "deaf": False}
        self.voice_state = {"self_mute": False, "self_deaf": False, "speaking": False}

    def emit_state(self):
        # speaking > deafened > muted > connected > tray
        state = "tray"
        if self.current_channel_id:
            state = "tray-connected"
            if self.settings.get("mute") or self.voice_state.get("self_mute"):
                state = "tray-muted"
            if self.settings.get("deaf") or self.voice_state.get("self_deaf"):
                state = "tray-deafened"
            if self.voice_state.get("speaking"):
                state = "tray-speaking"
        
        print(json.dumps({"state": state, "running": self.discord.connected}), flush=True)

    async def _send_cmd(self, cmd, args=None):
        nonce = self.discord._next_nonce()
        payload = {"cmd": cmd, "nonce": nonce}
        if args: payload["args"] = args
        self._pending[nonce] = cmd
        await self.discord.send_frame(OP_FRAME, payload)

    async def run(self):
        loop = asyncio.get_running_loop()
        
        def toggle_mute():
            if self.settings.get("deaf"):
                asyncio.create_task(self._send_cmd("SET_VOICE_SETTINGS", {"deaf": False, "mute": False}))
            else:
                new_mute = not self.settings.get("mute", False)
                asyncio.create_task(self._send_cmd("SET_VOICE_SETTINGS", {"mute": new_mute}))
            
        def toggle_deafen():
            new_deaf = not self.settings.get("deaf", False)
            asyncio.create_task(self._send_cmd("SET_VOICE_SETTINGS", {"deaf": new_deaf}))
            
        loop.add_signal_handler(signal.SIGUSR1, toggle_mute)
        loop.add_signal_handler(signal.SIGUSR2, toggle_deafen)

        while True:
            try:
                if not await self.discord.connect():
                    await asyncio.sleep(5)
                    continue
                
                self.emit_state()
                
                await self.discord.handshake(DEFAULT_CLIENT_ID)
                if token := (self.tokens.access_token or self.tokens.load()):
                    nonce = await self.discord.authenticate(token)
                    self._pending[nonce] = "AUTHENTICATE"
                else:
                    nonce = await self.discord.authorize(DEFAULT_CLIENT_ID, OAUTH_SCOPES)
                    self._pending[nonce] = "AUTHORIZE"
                
                await self._read_loop()
            except Exception as e:
                eprint(f"Error: {e}")
            finally:
                self.discord.close()
                self.authenticated = False
                self.current_channel_id = None
                self.emit_state()
                await asyncio.sleep(5)

    async def _read_loop(self):
        while self.discord.connected:
            op, data = await self.discord.recv_frame()
            if op == OP_CLOSE: break
            if op == OP_PING:
                await self.discord.send_frame(OP_PONG, data)
                continue
            
            await self._handle_message(data)

    async def _handle_message(self, data):
        nonce = data.get("nonce")
        cmd = data.get("cmd", "")
        evt = data.get("evt")
        
        if evt == "ERROR":
            msg = data.get("data", {}).get("message", "Unknown error")
            if nonce and self._pending.get(nonce) == "AUTHENTICATE":
                self.tokens.clear()
                n = await self.discord.authorize(DEFAULT_CLIENT_ID, OAUTH_SCOPES)
                self._pending[n] = "AUTHORIZE"
            eprint(f"Discord error: {msg}")
            return
            
        if nonce and nonce in self._pending:
            pcmd = self._pending.pop(nonce)
            await self._handle_response(pcmd, data)
            return

        if cmd == "DISPATCH" and evt:
            await self._handle_dispatch(evt, data.get("data", {}))

    async def _handle_response(self, cmd, data):
        resp = data.get("data", {})
        if cmd == "AUTHORIZE":
            code = resp.get("code")
            if code:
                token = await asyncio.get_running_loop().run_in_executor(None, TokenManager.exchange_code, code)
                self.tokens.save(token)
                n = await self.discord.authenticate(token)
                self._pending[n] = "AUTHENTICATE"
        elif cmd == "AUTHENTICATE":
            self.authenticated = True
            self.current_user_id = resp.get("user", {}).get("id")
            n1 = await self.discord.subscribe("VOICE_CHANNEL_SELECT")
            self._pending[n1] = "SUB"
            n2 = await self.discord.subscribe("VOICE_SETTINGS_UPDATE")
            self._pending[n2] = "SUB"
            await self._send_cmd("GET_SELECTED_VOICE_CHANNEL")
        elif cmd == "GET_SELECTED_VOICE_CHANNEL":
            if resp and resp.get("id"):
                await self._on_join(resp["id"], resp)
            else:
                await self._on_leave()
        elif cmd in ("GET_VOICE_SETTINGS", "SET_VOICE_SETTINGS"):
            self.settings["mute"] = resp.get("mute", False)
            self.settings["deaf"] = resp.get("deaf", False)
            self.emit_state()

    async def _subscribe_channel(self, channel_id):
        for evt in ("VOICE_STATE_UPDATE", "SPEAKING_START", "SPEAKING_STOP"):
            try:
                n = await self.discord.subscribe(evt, {"channel_id": channel_id})
                self._pending[n] = "SUB"
            except Exception: pass

    async def _unsubscribe_channel(self, channel_id):
        for evt in ("VOICE_STATE_UPDATE", "SPEAKING_START", "SPEAKING_STOP"):
            try:
                n = await self.discord.unsubscribe(evt, {"channel_id": channel_id})
                self._pending[n] = "UNSUB"
            except Exception: pass

    async def _on_join(self, channel_id, channel_data=None):
        if self.current_channel_id and self.current_channel_id != channel_id:
            await self._unsubscribe_channel(self.current_channel_id)
        self.current_channel_id = channel_id
        
        if channel_data and "voice_states" in channel_data:
            for vs in channel_data["voice_states"]:
                uid = vs.get("user", {}).get("id")
                if uid == self.current_user_id:
                    v = vs.get("voice_state", {})
                    self.voice_state["self_mute"] = v.get("self_mute", False)
                    self.voice_state["self_deaf"] = v.get("self_deaf", False)

        await self._subscribe_channel(channel_id)
        await self._send_cmd("GET_VOICE_SETTINGS")
        self.emit_state()

    async def _on_leave(self):
        if self.current_channel_id:
            await self._unsubscribe_channel(self.current_channel_id)
        self.current_channel_id = None
        self.emit_state()

    async def _handle_dispatch(self, evt, data):
        if evt == "VOICE_CHANNEL_SELECT":
            if data.get("channel_id"):
                await self._send_cmd("GET_SELECTED_VOICE_CHANNEL")
            else:
                await self._on_leave()
        elif evt == "VOICE_STATE_UPDATE":
            uid = data.get("user", {}).get("id")
            if uid == self.current_user_id:
                v = data.get("voice_state", {})
                self.voice_state["self_mute"] = v.get("self_mute", False)
                self.voice_state["self_deaf"] = v.get("self_deaf", False)
                self.emit_state()
        elif evt == "SPEAKING_START":
            if data.get("user_id") == self.current_user_id:
                self.voice_state["speaking"] = True
                self.emit_state()
        elif evt == "SPEAKING_STOP":
            if data.get("user_id") == self.current_user_id:
                self.voice_state["speaking"] = False
                self.emit_state()
        elif evt == "VOICE_SETTINGS_UPDATE":
            self.settings["mute"] = data.get("mute", False)
            self.settings["deaf"] = data.get("deaf", False)
            self.emit_state()

if __name__ == "__main__":
    bridge = DiscordBridge()
    try:
        asyncio.run(bridge.run())
    except KeyboardInterrupt:
        pass
