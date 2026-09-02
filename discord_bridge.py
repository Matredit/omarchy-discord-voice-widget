#!/usr/bin/env python3
import asyncio
import atexit
import ctypes
import json
import os
import re
import signal
import socket
import stat
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Ensure the process dies if the parent (omarchy-shell) dies
try:
    libc = ctypes.CDLL("libc.so.6")
    PR_SET_PDEATHSIG = 1
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
except Exception:
    pass

DEFAULT_CLIENT_ID = "207646673902501888"
OAUTH_SCOPES = ["rpc", "rpc.voice.read", "rpc.voice.write"]
TOKEN_EXCHANGE_URL = "https://streamkit.discord.com/overlay/token"
EXPECTED_ORIGIN = "streamkit.discord.com"

OP_HANDSHAKE = 0
OP_FRAME = 1
OP_CLOSE = 2
OP_PING = 3
OP_PONG = 4

# Security and Protocol Ceilings
MAX_FRAME_SIZE = 64 * 1024           # 64 KiB frame length ceiling
MAX_TOKEN_FILE_SIZE = 8 * 1024       # 8 KiB token cache ceiling
MAX_HTTP_RESPONSE_BYTES = 32 * 1024  # 32 KiB OAuth exchange ceiling
MAX_PID_FILE_SIZE = 4096             # 4 KiB PID record ceiling

# Lifecycle Deadlines (seconds)
CONNECT_TIMEOUT = 2.0
HANDSHAKE_TIMEOUT = 5.0
OPERATION_TIMEOUT = 10.0
IDLE_PING_INTERVAL = 30.0
PING_RESPONSE_TIMEOUT = 5.0

TOKEN_REGEX = re.compile(r"^[A-Za-z0-9_.\-]+$")
CODE_REGEX = re.compile(r"^[A-Za-z0-9_.\-]+$")

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, flush=True)

def verify_private_dir(path: str, create: bool = False, mode: int = 0o700) -> int:
    """
    Ensures path exists, is owned by current user, is not a symlink,
    and has restricted permissions. Returns dir_fd opened with O_DIRECTORY | O_NOFOLLOW.
    Caller must close the returned file descriptor.
    """
    uid = os.getuid()
    if create and not os.path.exists(path):
        try:
            os.makedirs(path, mode=mode, exist_ok=True)
        except OSError as e:
            raise RuntimeError(f"Failed to create directory {path}: {e}")

    try:
        dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise RuntimeError(f"Cannot safely open directory {path}: {e}")

    try:
        st = os.fstat(dir_fd)
        if not stat.S_ISDIR(st.st_mode):
            raise RuntimeError(f"Path is not a directory: {path}")
        if st.st_uid != uid:
            raise RuntimeError(f"Directory {path} owned by UID {st.st_uid}, expected {uid}")
        # Ensure not writable by others or group
        if (st.st_mode & 0o022) != 0:
            try:
                os.fchmod(dir_fd, mode)
            except OSError:
                pass
            st = os.fstat(dir_fd)
            if (st.st_mode & 0o022) != 0:
                raise RuntimeError(f"Directory {path} permissions too open: {oct(st.st_mode)}")
        return dir_fd
    except Exception:
        os.close(dir_fd)
        raise

def get_verified_runtime_dir() -> str:
    """
    Get a secure, verified runtime directory owned by the current user.
    Prefers XDG_RUNTIME_DIR if valid; otherwise creates/verifies /tmp/opoii_discord_<uid>.
    """
    uid = os.getuid()
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        try:
            st = os.lstat(xdg)
            if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_uid == uid:
                if (st.st_mode & 0o022) == 0:
                    return xdg
        except OSError:
            pass

    fallback = f"/tmp/opoii_discord_{uid}"
    try:
        os.mkdir(fallback, mode=0o700)
    except FileExistsError:
        pass
    except OSError as e:
        raise RuntimeError(f"Failed to create secure runtime directory {fallback}: {e}")

    st = os.lstat(fallback)
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise RuntimeError(f"Runtime dir {fallback} is not a directory or is a symlink")
    if st.st_uid != uid:
        raise RuntimeError(f"Runtime dir {fallback} owned by {st.st_uid}, expected {uid}")
    if (st.st_mode & 0o077) != 0:
        os.chmod(fallback, 0o700)
    return fallback


class PIDManager:
    PID_FILENAME = "discord_bridge.pid"

    @staticmethod
    def get_process_starttime(pid: int) -> int:
        try:
            with open(f"/proc/{pid}/stat", "r") as f:
                content = f.read()
            rparen = content.rfind(")")
            if rparen == -1:
                return 0
            fields = content[rparen + 2:].split()
            # field 22 of /proc/[pid]/stat is index 19 of fields after comm
            return int(fields[19])
        except Exception:
            return 0

    @classmethod
    def write_pid(cls) -> str:
        runtime_dir = get_verified_runtime_dir()
        dir_fd = verify_private_dir(runtime_dir, create=True, mode=0o700)
        temp_name = None
        try:
            pid = os.getpid()
            uid = os.getuid()
            starttime = cls.get_process_starttime(pid)
            record = {
                "pid": pid,
                "uid": uid,
                "starttime": starttime,
                "comm": "discord_bridge.py"
            }
            content = json.dumps(record, indent=2).encode("utf-8")

            temp_name = f".pid_{os.urandom(8).hex()}.tmp"
            tmp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=dir_fd
            )
            try:
                os.fchmod(tmp_fd, 0o600)
                os.write(tmp_fd, content)
                os.fsync(tmp_fd)
            finally:
                os.close(tmp_fd)

            os.replace(temp_name, cls.PID_FILENAME, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            temp_name = None
            return os.path.join(runtime_dir, cls.PID_FILENAME)
        except Exception:
            if temp_name:
                try:
                    os.unlink(temp_name, dir_fd=dir_fd)
                except OSError:
                    pass
            raise
        finally:
            os.close(dir_fd)

    @classmethod
    def remove_pid(cls):
        try:
            runtime_dir = get_verified_runtime_dir()
            dir_fd = verify_private_dir(runtime_dir, create=False)
        except Exception:
            return

        try:
            try:
                fd = os.open(cls.PID_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            except OSError:
                return

            try:
                st = os.fstat(fd)
                if stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_size <= MAX_PID_FILE_SIZE:
                    data = os.read(fd, MAX_PID_FILE_SIZE)
                    try:
                        record = json.loads(data.decode("utf-8"))
                        if record.get("pid") == os.getpid():
                            os.unlink(cls.PID_FILENAME, dir_fd=dir_fd)
                    except Exception:
                        pass
            finally:
                os.close(fd)
        finally:
            os.close(dir_fd)

    @classmethod
    def signal_bridge(cls, sig: signal.Signals) -> bool:
        """
        Safely validates the PID record against the live process immediately before signalling.
        Checks ownership, starttime, and executable identity.
        """
        try:
            runtime_dir = get_verified_runtime_dir()
            dir_fd = verify_private_dir(runtime_dir, create=False)
        except Exception as e:
            eprint(f"Error accessing runtime directory: {e}")
            return False

        try:
            try:
                fd = os.open(cls.PID_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            except FileNotFoundError:
                eprint("Discord bridge PID file not found.")
                return False
            except OSError as e:
                eprint(f"Error opening PID file: {e}")
                return False

            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    eprint("PID file is not a regular file.")
                    return False
                if st.st_uid != os.getuid():
                    eprint("PID file is not owned by current user.")
                    return False
                if st.st_size > MAX_PID_FILE_SIZE:
                    eprint("PID file exceeds size ceiling.")
                    return False
                data = os.read(fd, MAX_PID_FILE_SIZE)
            finally:
                os.close(fd)

            try:
                record = json.loads(data.decode("utf-8"))
            except Exception as e:
                eprint(f"Invalid JSON in PID file: {e}")
                return False

            if not isinstance(record, dict):
                eprint("PID file is not a JSON object.")
                return False

            pid = record.get("pid")
            uid = record.get("uid")
            starttime = record.get("starttime")

            if not isinstance(pid, int) or pid <= 1 or pid == os.getpid():
                eprint("Invalid PID in record.")
                return False
            if uid != os.getuid():
                eprint(f"PID record UID mismatch: record={uid}, current={os.getuid()}.")
                return False

            # Verify target process existence and ownership via /proc/[pid]/status
            try:
                with open(f"/proc/{pid}/status", "r") as f:
                    status_content = f.read()
            except FileNotFoundError:
                eprint(f"Process {pid} is not running (stale PID file). Cleaning up.")
                try:
                    os.unlink(cls.PID_FILENAME, dir_fd=dir_fd)
                except OSError:
                    pass
                return False
            except PermissionError:
                eprint(f"Permission denied inspecting /proc/{pid}.")
                return False

            real_uid = None
            for line in status_content.splitlines():
                if line.startswith("Uid:"):
                    real_uid = int(line.split()[1])
                    break
            if real_uid != os.getuid():
                eprint(f"Process {pid} UID {real_uid} does not match {os.getuid()}.")
                return False

            # Verify starttime to prevent PID reuse attacks
            proc_starttime = cls.get_process_starttime(pid)
            if starttime and proc_starttime and proc_starttime != starttime:
                eprint("Process starttime mismatch (PID recycled). Cleaning up stale PID file.")
                try:
                    os.unlink(cls.PID_FILENAME, dir_fd=dir_fd)
                except OSError:
                    pass
                return False

            # Verify executable identity via /proc/[pid]/cmdline
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmdline = f.read().decode("utf-8", errors="replace")
                if "discord_bridge" not in cmdline:
                    eprint(f"Process {pid} command line does not match discord_bridge: {cmdline}")
                    return False
            except Exception as e:
                eprint(f"Failed to inspect process cmdline: {e}")
                return False

            # Identity confirmed: safely deliver signal
            os.kill(pid, sig)
            return True
        finally:
            os.close(dir_fd)


class DiscordIPC:
    def __init__(self):
        self.reader = None
        self.writer = None
        self._nonce = 0

    @staticmethod
    def _candidate_paths():
        """
        Discovers candidate Discord IPC socket paths.
        Only allows paths located inside verified directories owned by current user.
        Rejects unsafe fallback paths like raw /tmp.
        """
        paths = []
        uid = os.getuid()
        dirs_to_check = []

        if xdg := os.environ.get("XDG_RUNTIME_DIR"):
            dirs_to_check.append(xdg)
            dirs_to_check.append(os.path.join(xdg, "app", "com.discordapp.Discord"))

        if snap := os.environ.get("SNAP_USER_DATA"):
            dirs_to_check.append(os.path.join(snap, ".config"))

        verified_dirs = []
        for d in dirs_to_check:
            try:
                st = os.lstat(d)
                if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                    if st.st_uid == uid and (st.st_mode & 0o022) == 0:
                        verified_dirs.append(d)
            except OSError:
                continue

        for d in verified_dirs:
            for i in range(10):
                sock_path = os.path.join(d, f"discord-ipc-{i}")
                try:
                    st = os.lstat(sock_path)
                    # Verify socket identity: must be a socket, not a symlink, owned by current UID
                    if stat.S_ISSOCK(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_uid == uid:
                        paths.append(sock_path)
                except OSError:
                    continue

        return paths

    async def connect(self):
        for path in self._candidate_paths():
            try:
                # Enforce bounded connect deadline
                r, w = await asyncio.wait_for(
                    asyncio.open_unix_connection(path),
                    timeout=CONNECT_TIMEOUT
                )
            except (OSError, asyncio.TimeoutError):
                continue

            # Verify peer identity on the connected socket via SO_PEERCRED
            try:
                sock = w.get_extra_info("socket")
                if sock is None:
                    w.close()
                    await w.wait_closed()
                    continue

                SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
                creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
                peer_pid, peer_uid, peer_gid = struct.unpack("3i", creds)

                if peer_uid != os.getuid():
                    eprint(f"Rejected socket {path}: peer UID {peer_uid} does not match {os.getuid()}")
                    w.close()
                    await w.wait_closed()
                    continue

                self.reader, self.writer = r, w
                return True
            except Exception as e:
                eprint(f"Error validating peer credentials on {path}: {e}")
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass
                continue
        return False

    def close(self):
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass
            self.writer = None
            self.reader = None

    @property
    def connected(self):
        return self.writer is not None and not self.writer.is_closing()

    async def send_frame(self, opcode, payload):
        if not self.writer:
            raise ConnectionError("Not connected")
        data = json.dumps(payload).encode("utf-8")
        if len(data) > MAX_FRAME_SIZE:
            raise ValueError(f"Payload size {len(data)} exceeds ceiling {MAX_FRAME_SIZE}")
        header = struct.pack("<II", opcode, len(data))
        self.writer.write(header + data)
        await asyncio.wait_for(self.writer.drain(), timeout=OPERATION_TIMEOUT)

    async def recv_frame(self, timeout=None):
        if not self.reader:
            raise ConnectionError("Not connected")

        # Read 8-byte header with timeout
        if timeout is not None:
            header = await asyncio.wait_for(self.reader.readexactly(8), timeout=timeout)
        else:
            header = await self.reader.readexactly(8)

        opcode, length = struct.unpack("<II", header)

        # Enforce small protocol frame ceiling BEFORE allocating payload buffer
        if length > MAX_FRAME_SIZE:
            raise ValueError(f"Frame length {length} exceeds maximum allowed ceiling {MAX_FRAME_SIZE}")
        if length < 0:
            raise ValueError(f"Invalid frame length: {length}")

        if opcode not in (OP_HANDSHAKE, OP_FRAME, OP_CLOSE, OP_PING, OP_PONG):
            raise ValueError(f"Invalid opcode: {opcode}")

        # Read payload with timeout
        if timeout is not None:
            data = await asyncio.wait_for(self.reader.readexactly(length), timeout=timeout)
        else:
            data = await self.reader.readexactly(length)

        if length == 0:
            return opcode, {}

        try:
            payload_text = data.decode("utf-8")
            payload = json.loads(payload_text)
        except Exception as e:
            raise ValueError(f"Malformed JSON frame payload: {e}")

        if not isinstance(payload, dict):
            raise ValueError(f"Frame payload is not a JSON object: {type(payload)}")

        return opcode, payload

    def _next_nonce(self):
        self._nonce += 1
        return str(self._nonce)

    async def handshake(self, client_id):
        await self.send_frame(OP_HANDSHAKE, {"v": 1, "client_id": client_id})
        op, data = await asyncio.wait_for(self.recv_frame(timeout=HANDSHAKE_TIMEOUT), timeout=HANDSHAKE_TIMEOUT)
        if op == OP_CLOSE:
            raise ConnectionError(f"Handshake closed: {data}")
        return data

    async def authorize(self, client_id, scopes):
        nonce = self._next_nonce()
        await self.send_frame(OP_FRAME, {
            "cmd": "AUTHORIZE",
            "args": {"client_id": client_id, "scopes": scopes, "prompt": "none"},
            "nonce": nonce
        })
        return nonce

    async def authenticate(self, access_token):
        nonce = self._next_nonce()
        await self.send_frame(OP_FRAME, {
            "cmd": "AUTHENTICATE",
            "args": {"access_token": access_token},
            "nonce": nonce
        })
        return nonce

    async def subscribe(self, evt, args=None):
        nonce = self._next_nonce()
        payload = {"cmd": "SUBSCRIBE", "evt": evt, "nonce": nonce}
        if args:
            payload["args"] = args
        await self.send_frame(OP_FRAME, payload)
        return nonce

    async def unsubscribe(self, evt, args=None):
        nonce = self._next_nonce()
        payload = {"cmd": "UNSUBSCRIBE", "evt": evt, "nonce": nonce}
        if args:
            payload["args"] = args
        await self.send_frame(OP_FRAME, payload)
        return nonce


class TokenManager:
    TOKEN_FILENAME = "token.json"

    def __init__(self):
        xdg_cache = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
        self._cache_dir = os.path.join(xdg_cache, "omarchy", "discord_plugin")
        self.access_token = None

    @staticmethod
    def _is_valid_token_string(token) -> bool:
        return isinstance(token, str) and 1 <= len(token) <= 512 and bool(TOKEN_REGEX.fullmatch(token))

    def load(self):
        try:
            dir_fd = verify_private_dir(self._cache_dir, create=False)
        except Exception:
            return None

        try:
            try:
                fd = os.open(self.TOKEN_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
            except OSError:
                return None

            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                    return None
                if (st.st_mode & 0o077) != 0:
                    try:
                        os.fchmod(fd, 0o600)
                    except OSError:
                        pass
                if st.st_size > MAX_TOKEN_FILE_SIZE:
                    return None
                data = os.read(fd, MAX_TOKEN_FILE_SIZE)
            finally:
                os.close(fd)

            try:
                parsed = json.loads(data.decode("utf-8"))
            except Exception:
                return None

            if not isinstance(parsed, dict):
                return None
            token = parsed.get("access_token")
            if not self._is_valid_token_string(token):
                return None
            self.access_token = token
            return token
        finally:
            os.close(dir_fd)

    def save(self, token):
        if not self._is_valid_token_string(token):
            raise ValueError("Invalid access token format")

        dir_fd = verify_private_dir(self._cache_dir, create=True, mode=0o700)
        temp_name = None
        try:
            payload = json.dumps({"access_token": token}).encode("utf-8")
            temp_name = f".token_{os.urandom(8).hex()}.tmp"
            tmp_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=dir_fd
            )
            try:
                os.fchmod(tmp_fd, 0o600)
                os.write(tmp_fd, payload)
                os.fsync(tmp_fd)
            finally:
                os.close(tmp_fd)

            os.replace(temp_name, self.TOKEN_FILENAME, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            self.access_token = token
            temp_name = None
        except Exception:
            if temp_name:
                try:
                    os.unlink(temp_name, dir_fd=dir_fd)
                except OSError:
                    pass
            raise
        finally:
            os.close(dir_fd)

    def clear(self):
        self.access_token = None
        try:
            dir_fd = verify_private_dir(self._cache_dir, create=False)
        except Exception:
            return

        try:
            try:
                os.unlink(self.TOKEN_FILENAME, dir_fd=dir_fd)
            except OSError:
                pass
        finally:
            os.close(dir_fd)

    @classmethod
    def exchange_code(cls, code: str) -> str:
        if not isinstance(code, str) or not (1 <= len(code) <= 256) or not CODE_REGEX.fullmatch(code):
            raise ValueError("Invalid authorization code format")

        body = json.dumps({"code": code}).encode("utf-8")
        req = urllib.request.Request(
            TOKEN_EXCHANGE_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "OmarchyDiscordWidget/1.0",
                "Accept": "application/json"
            },
            method="POST"
        )

        class StrictRedirectHandler(urllib.request.HTTPRedirectHandler):
            def __init__(self, max_redirects=0):
                super().__init__()
                self.max_redirects = max_redirects
                self.redirect_count = 0

            def redirect_request(self, req, fp, code, msg, headers, newurl):
                self.redirect_count += 1
                if self.redirect_count > self.max_redirects:
                    raise urllib.error.HTTPError(req.full_url, code, "Too many redirects", headers, fp)
                p = urllib.parse.urlparse(newurl)
                if p.scheme.lower() != "https":
                    raise urllib.error.HTTPError(req.full_url, code, "Redirect to non-HTTPS disallowed", headers, fp)
                if p.netloc.lower() != EXPECTED_ORIGIN:
                    raise urllib.error.HTTPError(req.full_url, code, f"Redirect to untrusted domain disallowed", headers, fp)
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        opener = urllib.request.build_opener(StrictRedirectHandler(max_redirects=0))

        try:
            with opener.open(req, timeout=5.0) as resp:
                final_url = resp.geturl()
                p = urllib.parse.urlparse(final_url)
                if p.scheme.lower() != "https":
                    raise ValueError(f"Insecure final scheme: {p.scheme}")
                if p.netloc.lower() != EXPECTED_ORIGIN:
                    raise ValueError(f"Untrusted final origin: {p.netloc}")

                data = resp.read(MAX_HTTP_RESPONSE_BYTES + 1)
                if len(data) > MAX_HTTP_RESPONSE_BYTES:
                    raise ValueError("OAuth response exceeded maximum byte ceiling")

                try:
                    parsed = json.loads(data.decode("utf-8"))
                except Exception as e:
                    raise ValueError(f"Failed to parse OAuth response JSON: {e}")

                if not isinstance(parsed, dict):
                    raise ValueError("OAuth response is not a JSON object")

                token = parsed.get("access_token")
                if not cls._is_valid_token_string(token):
                    raise ValueError("Invalid or missing access_token in OAuth response")
                return token
        except Exception as e:
            raise RuntimeError(f"Token exchange failed: {e}") from e


class DiscordBridge:
    def __init__(self):
        self.discord = DiscordIPC()
        self.tokens = TokenManager()
        self.authenticated = False
        self._pending = {}
        self.current_user_id = None
        self.current_channel_id = None
        self._shutdown_event = asyncio.Event()

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
        if args:
            payload["args"] = args
        self._pending[nonce] = (cmd, time.monotonic())
        await self.discord.send_frame(OP_FRAME, payload)

    def toggle_mute(self):
        if not self.discord.connected:
            return
        if self.settings.get("deaf"):
            asyncio.create_task(self._send_cmd("SET_VOICE_SETTINGS", {"deaf": False, "mute": False}))
        else:
            new_mute = not self.settings.get("mute", False)
            asyncio.create_task(self._send_cmd("SET_VOICE_SETTINGS", {"mute": new_mute}))

    def toggle_deafen(self):
        if not self.discord.connected:
            return
        new_deaf = not self.settings.get("deaf", False)
        asyncio.create_task(self._send_cmd("SET_VOICE_SETTINGS", {"deaf": new_deaf}))

    def request_shutdown(self):
        self._shutdown_event.set()
        self.discord.close()

    async def _stdin_loop(self):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            transport, _ = await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        except Exception as e:
            eprint(f"Could not initialize stdin reader: {e}")
            return

        try:
            while not self._shutdown_event.is_set():
                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode("utf-8", errors="replace").strip()
                if cmd == "toggle_mute":
                    self.toggle_mute()
                elif cmd == "toggle_deafen":
                    self.toggle_deafen()
        except Exception as e:
            eprint(f"Stdin reader error: {e}")
        finally:
            transport.close()

    async def run(self):
        loop = asyncio.get_running_loop()

        # Register signals for shutdown and hotkey toggling
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            try:
                loop.add_signal_handler(sig, self.request_shutdown)
            except (NotImplementedError, RuntimeError):
                pass

        try:
            loop.add_signal_handler(signal.SIGUSR1, self.toggle_mute)
            loop.add_signal_handler(signal.SIGUSR2, self.toggle_deafen)
        except (NotImplementedError, RuntimeError):
            pass

        # Write identity-bound PID record
        try:
            PIDManager.write_pid()
            atexit.register(PIDManager.remove_pid)
        except Exception as e:
            eprint(f"Warning: Could not write PID record: {e}")

        stdin_task = asyncio.create_task(self._stdin_loop())

        try:
            while not self._shutdown_event.is_set():
                try:
                    if not await self.discord.connect():
                        try:
                            await asyncio.wait_for(self._shutdown_event.wait(), timeout=5.0)
                        except asyncio.TimeoutError:
                            pass
                        continue

                    self.emit_state()

                    await self.discord.handshake(DEFAULT_CLIENT_ID)
                    token = self.tokens.access_token or self.tokens.load()
                    if token:
                        nonce = await self.discord.authenticate(token)
                        self._pending[nonce] = ("AUTHENTICATE", time.monotonic())
                    else:
                        nonce = await self.discord.authorize(DEFAULT_CLIENT_ID, OAUTH_SCOPES)
                        self._pending[nonce] = ("AUTHORIZE", time.monotonic())

                    await self._read_loop()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    eprint(f"Bridge error: {e}")
                finally:
                    self.discord.close()
                    self.authenticated = False
                    self.current_channel_id = None
                    self.emit_state()
                    if not self._shutdown_event.is_set():
                        try:
                            await asyncio.wait_for(self._shutdown_event.wait(), timeout=5.0)
                        except asyncio.TimeoutError:
                            pass
        finally:
            stdin_task.cancel()
            self.discord.close()
            self.emit_state()
            PIDManager.remove_pid()

    async def _read_loop(self):
        while self.discord.connected and not self._shutdown_event.is_set():
            try:
                op, data = await self.discord.recv_frame(timeout=IDLE_PING_INTERVAL)
            except asyncio.TimeoutError:
                # Send OP_PING heartbeat to verify connection is still alive
                try:
                    await self.discord.send_frame(OP_PING, {"nonce": self.discord._next_nonce()})
                    op, data = await self.discord.recv_frame(timeout=PING_RESPONSE_TIMEOUT)
                except (asyncio.TimeoutError, Exception) as e:
                    eprint(f"Discord ping heartbeat timed out/failed: {e}")
                    break

            if op == OP_CLOSE:
                break
            if op == OP_PING:
                await self.discord.send_frame(OP_PONG, data)
                continue
            if op == OP_PONG:
                continue

            await self._handle_message(data)

    async def _handle_message(self, data):
        nonce = data.get("nonce")
        cmd = data.get("cmd", "")
        evt = data.get("evt")

        if evt == "ERROR":
            msg = data.get("data", {}).get("message", "Unknown error")
            if nonce and nonce in self._pending:
                pcmd, _ = self._pending.pop(nonce)
                if pcmd == "AUTHENTICATE":
                    self.tokens.clear()
                    n = await self.discord.authorize(DEFAULT_CLIENT_ID, OAUTH_SCOPES)
                    self._pending[n] = ("AUTHORIZE", time.monotonic())
            eprint(f"Discord error: {msg}")
            return

        if nonce and nonce in self._pending:
            pcmd, _ = self._pending.pop(nonce)
            await self._handle_response(pcmd, data)
            return

        if cmd == "DISPATCH" and evt:
            await self._handle_dispatch(evt, data.get("data", {}))

    async def _handle_response(self, cmd, data):
        resp = data.get("data", {})
        if not isinstance(resp, dict):
            return

        if cmd == "AUTHORIZE":
            code = resp.get("code")
            if code and isinstance(code, str):
                loop = asyncio.get_running_loop()
                token = await asyncio.wait_for(
                    loop.run_in_executor(None, TokenManager.exchange_code, code),
                    timeout=OPERATION_TIMEOUT
                )
                self.tokens.save(token)
                n = await self.discord.authenticate(token)
                self._pending[n] = ("AUTHENTICATE", time.monotonic())
        elif cmd == "AUTHENTICATE":
            self.authenticated = True
            self.current_user_id = resp.get("user", {}).get("id")
            n1 = await self.discord.subscribe("VOICE_CHANNEL_SELECT")
            self._pending[n1] = ("SUB", time.monotonic())
            n2 = await self.discord.subscribe("VOICE_SETTINGS_UPDATE")
            self._pending[n2] = ("SUB", time.monotonic())
            await self._send_cmd("GET_SELECTED_VOICE_CHANNEL")
        elif cmd == "GET_SELECTED_VOICE_CHANNEL":
            if resp and resp.get("id"):
                await self._on_join(resp["id"], resp)
            else:
                await self._on_leave()
        elif cmd in ("GET_VOICE_SETTINGS", "SET_VOICE_SETTINGS"):
            self.settings["mute"] = bool(resp.get("mute", False))
            self.settings["deaf"] = bool(resp.get("deaf", False))
            self.emit_state()

    async def _subscribe_channel(self, channel_id):
        for evt in ("VOICE_STATE_UPDATE", "SPEAKING_START", "SPEAKING_STOP"):
            try:
                n = await self.discord.subscribe(evt, {"channel_id": channel_id})
                self._pending[n] = ("SUB", time.monotonic())
            except Exception:
                pass

    async def _unsubscribe_channel(self, channel_id):
        for evt in ("VOICE_STATE_UPDATE", "SPEAKING_START", "SPEAKING_STOP"):
            try:
                n = await self.discord.unsubscribe(evt, {"channel_id": channel_id})
                self._pending[n] = ("UNSUB", time.monotonic())
            except Exception:
                pass

    async def _on_join(self, channel_id, channel_data=None):
        if self.current_channel_id and self.current_channel_id != channel_id:
            await self._unsubscribe_channel(self.current_channel_id)
        self.current_channel_id = channel_id

        if channel_data and isinstance(channel_data.get("voice_states"), list):
            for vs in channel_data["voice_states"]:
                if isinstance(vs, dict) and vs.get("user", {}).get("id") == self.current_user_id:
                    v = vs.get("voice_state", {})
                    if isinstance(v, dict):
                        self.voice_state["self_mute"] = bool(v.get("self_mute", False))
                        self.voice_state["self_deaf"] = bool(v.get("self_deaf", False))

        await self._subscribe_channel(channel_id)
        await self._send_cmd("GET_VOICE_SETTINGS")
        self.emit_state()

    async def _on_leave(self):
        if self.current_channel_id:
            await self._unsubscribe_channel(self.current_channel_id)
        self.current_channel_id = None
        self.voice_state["speaking"] = False
        self.emit_state()

    async def _handle_dispatch(self, evt, data):
        if not isinstance(data, dict):
            return

        if evt == "VOICE_CHANNEL_SELECT":
            if data.get("channel_id"):
                await self._send_cmd("GET_SELECTED_VOICE_CHANNEL")
            else:
                await self._on_leave()
        elif evt == "VOICE_STATE_UPDATE":
            uid = data.get("user", {}).get("id")
            if uid == self.current_user_id:
                v = data.get("voice_state", {})
                if isinstance(v, dict):
                    self.voice_state["self_mute"] = bool(v.get("self_mute", False))
                    self.voice_state["self_deaf"] = bool(v.get("self_deaf", False))
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
            self.settings["mute"] = bool(data.get("mute", False))
            self.settings["deaf"] = bool(data.get("deaf", False))
            self.emit_state()


def main():
    if "--toggle-mute" in sys.argv:
        success = PIDManager.signal_bridge(signal.SIGUSR1)
        sys.exit(0 if success else 1)
    elif "--toggle-deafen" in sys.argv:
        success = PIDManager.signal_bridge(signal.SIGUSR2)
        sys.exit(0 if success else 1)

    bridge = DiscordBridge()
    try:
        asyncio.run(bridge.run())
    except KeyboardInterrupt:
        pass
    finally:
        PIDManager.remove_pid()


if __name__ == "__main__":
    main()
