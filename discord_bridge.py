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
CONNECTION_INIT_TIMEOUT = 15.0
OPERATION_TIMEOUT = 10.0
READ_PAYLOAD_TIMEOUT = 5.0
IDLE_PING_INTERVAL = 30.0
PING_RESPONSE_TIMEOUT = 5.0
OAUTH_OVERALL_TIMEOUT = 10.0
MAX_REDIRECTS = 3

TOKEN_REGEX = re.compile(r"^[A-Za-z0-9_.\-]+$")
CODE_REGEX = re.compile(r"^[A-Za-z0-9_.\-]+$")


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, flush=True)


def safe_dict(obj, key) -> dict:
    """Safely retrieves a dictionary field without risking AttributeError on non-dict types."""
    if isinstance(obj, dict):
        val = obj.get(key)
        if isinstance(val, dict):
            return val
    return {}


def validate_frame_payload(payload: dict) -> dict:
    """Validates structural bounds on frame schema fields."""
    if not isinstance(payload, dict):
        raise ValueError("Frame payload must be a JSON object")
    cmd = payload.get("cmd")
    if cmd is not None and (not isinstance(cmd, str) or len(cmd) > 64):
        raise ValueError(f"Invalid or oversized cmd in frame payload: {type(cmd)}")
    evt = payload.get("evt")
    if evt is not None and (not isinstance(evt, str) or len(evt) > 64):
        raise ValueError(f"Invalid or oversized evt in frame payload: {type(evt)}")
    nonce = payload.get("nonce")
    if nonce is not None and (not isinstance(nonce, (str, int)) or len(str(nonce)) > 64):
        raise ValueError(f"Invalid or oversized nonce in frame payload: {type(nonce)}")
    return payload


def verify_private_dir(path: str, create: bool = False, mode: int = 0o700) -> int:
    """
    Ensures the entire directory chain from root to path is verified:
    - Traversed component-by-component with O_NOFOLLOW and dir_fd.
    - Rejects any symlinks in intermediate or leaf components.
    - Ensures user-owned directories have restricted permissions and sets them if needed.
    - Ensures system/root-owned directories are not world-writable without sticky bit.
    - If create=True, creates missing directories descriptor-relatively with mode.
    Returns dir_fd opened with O_DIRECTORY | O_NOFOLLOW. Caller must close it.
    """
    path = os.path.abspath(path)
    parts = []
    curr = path
    while curr not in ("/", ""):
        curr, tail = os.path.split(curr)
        if tail:
            parts.append(tail)
    parts.reverse()

    uid = os.getuid()
    try:
        cur_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as e:
        raise RuntimeError(f"Cannot safely open root directory: {e}")

    try:
        for idx, part in enumerate(parts):
            is_leaf = (idx == len(parts) - 1)
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cur_fd)
            except FileNotFoundError:
                if not create:
                    raise
                part_mode = mode if is_leaf else 0o700
                try:
                    os.mkdir(part, mode=part_mode, dir_fd=cur_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cur_fd)

            st = os.fstat(next_fd)
            if not stat.S_ISDIR(st.st_mode):
                os.close(next_fd)
                raise RuntimeError(f"Path component {part} is not a directory")

            if st.st_uid == uid:
                if is_leaf:
                    if (st.st_mode & 0o077) != 0:
                        try:
                            os.fchmod(next_fd, mode)
                        except OSError:
                            pass
                else:
                    if (st.st_mode & 0o022) != 0:
                        try:
                            os.fchmod(next_fd, 0o700)
                        except OSError:
                            pass
            else:
                if (st.st_mode & 0o002) != 0 and not (st.st_mode & stat.S_ISVTX):
                    os.close(next_fd)
                    raise RuntimeError(f"Component {part} is world-writable without sticky bit")

            os.close(cur_fd)
            cur_fd = next_fd

        return cur_fd
    except Exception:
        os.close(cur_fd)
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
            dir_fd = verify_private_dir(xdg, create=False)
            os.close(dir_fd)
            return xdg
        except Exception:
            pass

    fallback = f"/tmp/opoii_discord_{uid}"
    try:
        dir_fd = verify_private_dir(fallback, create=True, mode=0o700)
        os.close(dir_fd)
        return fallback
    except Exception as e:
        raise RuntimeError(f"Failed to establish secure runtime directory {fallback}: {e}")



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
            try:
                st = os.stat(cls.PID_FILENAME, dir_fd=dir_fd, follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    os.unlink(cls.PID_FILENAME, dir_fd=dir_fd)
            except FileNotFoundError:
                pass

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

            try:
                os.chmod(cls.PID_FILENAME, 0o600, dir_fd=dir_fd, follow_symlinks=False)
            except OSError:
                pass

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
                    data = os.read(fd, MAX_PID_FILE_SIZE + 1)
                    if len(data) <= MAX_PID_FILE_SIZE:
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
        if sig not in (signal.SIGUSR1, signal.SIGUSR2, signal.SIGTERM):
            eprint(f"Invalid signal {sig} requested.")
            return False

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
                data = os.read(fd, MAX_PID_FILE_SIZE + 1)
                if len(data) > MAX_PID_FILE_SIZE:
                    eprint("PID file read exceeded size ceiling.")
                    return False
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
            if not isinstance(starttime, int) or starttime <= 0:
                eprint(f"PID record starttime invalid or missing: {starttime}.")
                return False

            # Verify target process existence and ownership via /proc/[pid]/status
            try:
                with open(f"/proc/{pid}/status", "r") as f:
                    status_content = f.read()
            except FileNotFoundError:
                eprint(f"Process {pid} is not running (stale PID file). Cleaning up.")
                try:
                    s_fd = os.open(cls.PID_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
                    try:
                        s_data = os.read(s_fd, MAX_PID_FILE_SIZE)
                        s_rec = json.loads(s_data.decode("utf-8"))
                        if s_rec.get("pid") == pid:
                            os.unlink(cls.PID_FILENAME, dir_fd=dir_fd)
                    finally:
                        os.close(s_fd)
                except Exception:
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
            if proc_starttime <= 0 or proc_starttime != starttime:
                eprint("Process starttime mismatch (PID recycled). Cleaning up stale PID file.")
                try:
                    s_fd = os.open(cls.PID_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
                    try:
                        s_data = os.read(s_fd, MAX_PID_FILE_SIZE)
                        s_rec = json.loads(s_data.decode("utf-8"))
                        if s_rec.get("pid") == pid and s_rec.get("starttime") == starttime:
                            os.unlink(cls.PID_FILENAME, dir_fd=dir_fd)
                    finally:
                        os.close(s_fd)
                except Exception:
                    pass
                return False

            # Verify executable identity via /proc/[pid]/cmdline
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    raw_cmdline = f.read(4096)
                cmdline_args = [arg.decode("utf-8", errors="replace") for arg in raw_cmdline.split(b"\0") if arg]
                if not any("discord_bridge" in arg for arg in cmdline_args):
                    eprint(f"Process {pid} command line does not match discord_bridge: {cmdline_args}")
                    return False
            except Exception as e:
                eprint(f"Failed to inspect process cmdline: {e}")
                return False

            # Verify binary identity via /proc/[pid]/exe if accessible
            try:
                exe_target = os.path.realpath(f"/proc/{pid}/exe")
                if "python" not in os.path.basename(exe_target).lower():
                    eprint(f"Process {pid} executable {exe_target} is not Python.")
                    return False
            except OSError:
                pass

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

        for d in dirs_to_check:
            try:
                dir_fd = verify_private_dir(d, create=False)
            except Exception:
                continue

            try:
                for i in range(10):
                    sock_name = f"discord-ipc-{i}"
                    try:
                        st = os.stat(sock_name, dir_fd=dir_fd, follow_symlinks=False)
                        if stat.S_ISSOCK(st.st_mode) and st.st_uid == uid:
                            paths.append(os.path.join(d, sock_name))
                    except OSError:
                        continue
            finally:
                os.close(dir_fd)

        return paths

    async def connect(self):
        for path in self._candidate_paths():
            try:
                st = os.lstat(path)
                if not stat.S_ISSOCK(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != os.getuid():
                    continue
            except OSError:
                continue

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

                if peer_pid <= 0:
                    eprint(f"Rejected socket {path}: invalid peer PID {peer_pid}")
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

    async def recv_frame(self, timeout=OPERATION_TIMEOUT):
        if not self.reader:
            raise ConnectionError("Not connected")

        async def _read_frame():
            header = await self.reader.readexactly(8)
            opcode, length = struct.unpack("<II", header)

            # Enforce small protocol frame ceiling BEFORE allocating/reading payload buffer
            if length > MAX_FRAME_SIZE:
                raise ValueError(f"Frame length {length} exceeds maximum allowed ceiling {MAX_FRAME_SIZE}")
            if length < 0:
                raise ValueError(f"Invalid frame length: {length}")

            if opcode not in (OP_HANDSHAKE, OP_FRAME, OP_CLOSE, OP_PING, OP_PONG):
                raise ValueError(f"Invalid opcode: {opcode}")

            if length == 0:
                return opcode, {}

            # Read payload with bounded per-read deadline
            data = await asyncio.wait_for(
                self.reader.readexactly(length),
                timeout=READ_PAYLOAD_TIMEOUT
            )

            try:
                payload_text = data.decode("utf-8")
                payload = json.loads(payload_text)
            except Exception as e:
                raise ValueError(f"Malformed JSON frame payload: {e}")

            if not isinstance(payload, dict):
                raise ValueError(f"Frame payload is not a JSON object: {type(payload)}")

            return opcode, validate_frame_payload(payload)

        eff_timeout = timeout if timeout is not None else OPERATION_TIMEOUT
        return await asyncio.wait_for(_read_frame(), timeout=eff_timeout)

    def _next_nonce(self):
        self._nonce += 1
        return str(self._nonce)

    async def handshake(self, client_id):
        await self.send_frame(OP_HANDSHAKE, {"v": 1, "client_id": client_id})
        op, data = await asyncio.wait_for(self.recv_frame(timeout=HANDSHAKE_TIMEOUT), timeout=HANDSHAKE_TIMEOUT)
        if op == OP_CLOSE:
            raise ConnectionError(f"Handshake closed: {data}")
        if op != OP_FRAME:
            raise ConnectionError(f"Handshake returned unexpected opcode {op}")

        # Validate authentic Discord READY dispatch
        cmd = data.get("cmd")
        evt = data.get("evt")
        if cmd != "DISPATCH" or evt != "READY":
            raise ConnectionError(f"Handshake response is not a Discord READY dispatch (cmd={cmd}, evt={evt})")

        resp_data = safe_dict(data, "data")
        config = safe_dict(resp_data, "config")
        cdn = str(config.get("cdn_host") or "")
        api = str(config.get("api_endpoint") or "")
        if not ("discord" in cdn or "discord" in api):
            raise ConnectionError("Handshake response lacks authentic Discord endpoints in config")

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
                data = os.read(fd, MAX_TOKEN_FILE_SIZE + 1)
                if len(data) > MAX_TOKEN_FILE_SIZE:
                    return None
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
            try:
                st = os.stat(self.TOKEN_FILENAME, dir_fd=dir_fd, follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    os.unlink(self.TOKEN_FILENAME, dir_fd=dir_fd)
            except FileNotFoundError:
                pass

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

            try:
                os.chmod(self.TOKEN_FILENAME, 0o600, dir_fd=dir_fd, follow_symlinks=False)
            except OSError:
                pass
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

        try:
            init_p = urllib.parse.urlparse(TOKEN_EXCHANGE_URL)
            if init_p.scheme.lower() != "https":
                raise ValueError(f"Insecure final scheme: {init_p.scheme}")
            if init_p.netloc.lower() != EXPECTED_ORIGIN:
                raise ValueError(f"Untrusted final origin: {init_p.netloc}")

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
                def __init__(self, max_redirects=MAX_REDIRECTS):
                    super().__init__()
                    self.max_redirects = max_redirects
                    self.redirect_count = 0

                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    self.redirect_count += 1
                    if self.redirect_count > self.max_redirects:
                        if fp:
                            try:
                                fp.close()
                            except Exception:
                                pass
                        raise urllib.error.HTTPError(req.full_url, code, "Too many redirects", headers, None)

                    resolved = urllib.parse.urljoin(req.full_url, newurl)
                    p = urllib.parse.urlparse(resolved)
                    if p.scheme.lower() != "https":
                        if fp:
                            try:
                                fp.close()
                            except Exception:
                                pass
                        raise urllib.error.HTTPError(req.full_url, code, "Redirect to non-HTTPS disallowed", headers, None)
                    if p.netloc.lower() != EXPECTED_ORIGIN:
                        if fp:
                            try:
                                fp.close()
                            except Exception:
                                pass
                        raise urllib.error.HTTPError(req.full_url, code, "Redirect to untrusted domain disallowed", headers, None)
                    return super().redirect_request(req, fp, code, msg, headers, resolved)

            opener = urllib.request.build_opener(StrictRedirectHandler(max_redirects=MAX_REDIRECTS))

            start_time = time.monotonic()
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

                if time.monotonic() - start_time > OAUTH_OVERALL_TIMEOUT:
                    raise TimeoutError("OAuth token exchange exceeded overall deadline")

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
        except urllib.error.HTTPError as e:
            msg = str(e)
            try:
                e.close()
            except Exception:
                pass
            raise RuntimeError(f"Token exchange failed: {msg}") from e
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
        reader = asyncio.StreamReader(limit=1024)
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
        except asyncio.CancelledError:
            pass
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

                    # Bound connection setup and initialization
                    async with asyncio.timeout(CONNECTION_INIT_TIMEOUT):
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
                except (asyncio.TimeoutError, TimeoutError) as e:
                    eprint(f"Bridge connection/operation timed out: {e}")
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
            # Check for expired pending operations
            now = time.monotonic()
            expired = [n for n, (c, t) in self._pending.items() if now - t > OPERATION_TIMEOUT]
            for n in expired:
                cmd, _ = self._pending.pop(n)
                eprint(f"Command {cmd} timed out waiting for response")
                if cmd in ("AUTHENTICATE", "AUTHORIZE"):
                    return

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
            except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                break
            except Exception as e:
                eprint(f"Frame read error: {e}")
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
        cmd = str(data.get("cmd") or "")
        evt = data.get("evt")

        if evt == "ERROR":
            resp_data = safe_dict(data, "data")
            msg = str(resp_data.get("message") or "Unknown error")
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
            await self._handle_dispatch(evt, safe_dict(data, "data"))

    async def _handle_response(self, cmd, data):
        resp = safe_dict(data, "data")

        if cmd == "AUTHORIZE":
            code = resp.get("code")
            if code and isinstance(code, str):
                loop = asyncio.get_running_loop()
                try:
                    token = await asyncio.wait_for(
                        loop.run_in_executor(None, TokenManager.exchange_code, code),
                        timeout=OPERATION_TIMEOUT
                    )
                    self.tokens.save(token)
                    n = await self.discord.authenticate(token)
                    self._pending[n] = ("AUTHENTICATE", time.monotonic())
                except Exception as e:
                    eprint(f"OAuth code exchange or authentication failed: {e}")
        elif cmd == "AUTHENTICATE":
            self.authenticated = True
            user = safe_dict(resp, "user")
            self.current_user_id = user.get("id")
            n1 = await self.discord.subscribe("VOICE_CHANNEL_SELECT")
            self._pending[n1] = ("SUB", time.monotonic())
            n2 = await self.discord.subscribe("VOICE_SETTINGS_UPDATE")
            self._pending[n2] = ("SUB", time.monotonic())
            await self._send_cmd("GET_SELECTED_VOICE_CHANNEL")
        elif cmd == "GET_SELECTED_VOICE_CHANNEL":
            if resp and resp.get("id"):
                await self._on_join(str(resp["id"]), resp)
            else:
                await self._on_leave()
        elif cmd in ("GET_VOICE_SETTINGS", "SET_VOICE_SETTINGS"):
            self.settings["mute"] = bool(resp.get("mute", False))
            self.settings["deaf"] = bool(resp.get("deaf", False))
            self.emit_state()

    async def _subscribe_channel(self, channel_id):
        for evt in ("VOICE_STATE_UPDATE", "SPEAKING_START", "SPEAKING_STOP"):
            try:
                n = await self.discord.subscribe(evt, {"channel_id": str(channel_id)})
                self._pending[n] = ("SUB", time.monotonic())
            except Exception:
                pass

    async def _unsubscribe_channel(self, channel_id):
        for evt in ("VOICE_STATE_UPDATE", "SPEAKING_START", "SPEAKING_STOP"):
            try:
                n = await self.discord.unsubscribe(evt, {"channel_id": str(channel_id)})
                self._pending[n] = ("UNSUB", time.monotonic())
            except Exception:
                pass

    async def _on_join(self, channel_id, channel_data=None):
        channel_id_str = str(channel_id)
        if self.current_channel_id and self.current_channel_id != channel_id_str:
            await self._unsubscribe_channel(self.current_channel_id)
        self.current_channel_id = channel_id_str

        if channel_data and isinstance(channel_data.get("voice_states"), list):
            for vs in channel_data["voice_states"]:
                if isinstance(vs, dict):
                    user = safe_dict(vs, "user")
                    if user.get("id") == self.current_user_id:
                        v = safe_dict(vs, "voice_state")
                        self.voice_state["self_mute"] = bool(v.get("self_mute", False))
                        self.voice_state["self_deaf"] = bool(v.get("self_deaf", False))

        await self._subscribe_channel(channel_id_str)
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
            cid = data.get("channel_id")
            if cid:
                await self._send_cmd("GET_SELECTED_VOICE_CHANNEL")
            else:
                await self._on_leave()
        elif evt == "VOICE_STATE_UPDATE":
            user = safe_dict(data, "user")
            if user.get("id") == self.current_user_id:
                v = safe_dict(data, "voice_state")
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
