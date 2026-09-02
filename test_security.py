import asyncio
import http.server
import json
import os
import signal
import socket
import stat
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from discord_bridge import (
    DiscordIPC,
    TokenManager,
    PIDManager,
    DiscordBridge,
    verify_private_dir,
    get_verified_runtime_dir,
    MAX_FRAME_SIZE,
    MAX_TOKEN_FILE_SIZE,
    MAX_HTTP_RESPONSE_BYTES,
    OP_HANDSHAKE,
    OP_FRAME,
    OP_PING,
    OP_PONG,
)


class TestDiscordIPCSecurity(unittest.IsolatedAsyncioTestCase):
    async def test_frame_length_ceiling_enforced_before_read(self):
        """Item 1: Verify frame length ceiling rejects huge frames without allocating."""
        reader = asyncio.StreamReader()
        writer = None  # mock
        ipc = DiscordIPC()
        ipc.reader = reader

        # Feed header with huge length (e.g. 100 MiB)
        huge_len = 100 * 1024 * 1024
        header = struct.pack("<II", OP_FRAME, huge_len)
        reader.feed_data(header)

        with self.assertRaises(ValueError) as ctx:
            await ipc.recv_frame(timeout=1.0)
        self.assertIn("exceeds maximum allowed ceiling", str(ctx.exception))

    async def test_recv_frame_rejects_invalid_opcode(self):
        """Item 1: Verify invalid opcode is rejected."""
        reader = asyncio.StreamReader()
        ipc = DiscordIPC()
        ipc.reader = reader

        invalid_opcode = 99
        header = struct.pack("<II", invalid_opcode, 2)
        reader.feed_data(header + b"{}")

        with self.assertRaises(ValueError) as ctx:
            await ipc.recv_frame(timeout=1.0)
        self.assertIn("Invalid opcode", str(ctx.exception))

    async def test_recv_frame_validates_json_schema(self):
        """Item 1: Verify malformed JSON or non-dict payloads are rejected."""
        reader = asyncio.StreamReader()
        ipc = DiscordIPC()
        ipc.reader = reader

        # Non-dict JSON (array)
        payload = b"[1, 2, 3]"
        header = struct.pack("<II", OP_FRAME, len(payload))
        reader.feed_data(header + payload)

        with self.assertRaises(ValueError) as ctx:
            await ipc.recv_frame(timeout=1.0)
        self.assertIn("not a JSON object", str(ctx.exception))

        # Malformed JSON
        payload = b"{not json}"
        header = struct.pack("<II", OP_FRAME, len(payload))
        reader.feed_data(header + payload)

        with self.assertRaises(ValueError) as ctx:
            await ipc.recv_frame(timeout=1.0)
        self.assertIn("Malformed JSON", str(ctx.exception))

    def test_candidate_paths_rejects_unsafe_fallbacks(self):
        """Item 1: Ensure raw /tmp and unverified dirs are rejected."""
        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": "", "SNAP_USER_DATA": "", "TMPDIR": "/tmp"}):
            paths = DiscordIPC._candidate_paths()
            for p in paths:
                self.assertFalse(p.startswith("/tmp/discord-ipc-"), "Raw /tmp must not be used as fallback")

    async def test_connect_verifies_peer_cred(self):
        """Item 1: Verify peer UID identity check via SO_PEERCRED on UNIX connection."""
        with tempfile.TemporaryDirectory() as td:
            sock_path = os.path.join(td, "discord-ipc-0")
            client_connected = asyncio.Event()
            client_writer = None

            async def handle_client(r, w):
                nonlocal client_writer
                client_writer = w
                client_connected.set()

            server = await asyncio.start_unix_server(handle_client, path=sock_path)
            ipc = DiscordIPC()

            with patch.object(DiscordIPC, "_candidate_paths", return_value=[sock_path]):
                connected = await ipc.connect()
                self.assertTrue(connected)
                self.assertTrue(ipc.connected)
                await client_connected.wait()
                ipc.close()

            if client_writer:
                client_writer.close()
                await client_writer.wait_closed()

            server.close()
            await server.wait_closed()
            await asyncio.sleep(0.01)

    async def test_connect_rejects_peer_uid_mismatch(self):
        """Item 1: Ensure connect rejects socket if peer UID does not match current user."""
        with tempfile.TemporaryDirectory() as td:
            sock_path = os.path.join(td, "discord-ipc-0")

            client_connected = asyncio.Event()

            async def handle_client(r, w):
                client_connected.set()
                try:
                    await r.read(1)
                except Exception:
                    pass
                finally:
                    w.close()
                    await w.wait_closed()

            server = await asyncio.start_unix_server(handle_client, path=sock_path)
            ipc = DiscordIPC()

            # Mock SO_PEERCRED to return a different UID (e.g. 9999)
            fake_cred = struct.pack("3i", 1234, 9999, 9999)
            with patch("socket.socket.getsockopt", return_value=fake_cred):
                with patch.object(DiscordIPC, "_candidate_paths", return_value=[sock_path]):
                    connected = await ipc.connect()
                    self.assertFalse(connected)
                    self.assertFalse(ipc.connected)

            ipc.close()
            server.close()
            await server.wait_closed()

    async def test_handshake_timeout_on_unresponsive_socket(self):
        """Item 5: Handshake deadline ensures bridge doesn't hang indefinitely on false socket."""
        with tempfile.TemporaryDirectory() as td:
            sock_path = os.path.join(td, "discord-ipc-0")

            async def silent_client(r, w):
                try:
                    await asyncio.sleep(1)
                except asyncio.CancelledError:
                    pass
                finally:
                    w.close()
                    await w.wait_closed()

            server = await asyncio.start_unix_server(silent_client, path=sock_path)
            ipc = DiscordIPC()

            with patch.object(DiscordIPC, "_candidate_paths", return_value=[sock_path]):
                connected = await ipc.connect()
                self.assertTrue(connected)

            with patch("discord_bridge.HANDSHAKE_TIMEOUT", 0.1):
                with self.assertRaises(asyncio.TimeoutError):
                    await ipc.handshake("test_client")

            ipc.close()
            server.close()
            await server.wait_closed()


class TestTokenManagerSecurity(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tm = TokenManager()
        self.tm._cache_dir = os.path.join(self.td.name, "discord_plugin")

    def tearDown(self):
        self.td.cleanup()

    def test_save_creates_mode_0600_private_file(self):
        """Item 2: Token saving uses mode 0600 temp file and verified private dir."""
        token = "secret_access_token_12345"
        self.tm.save(token)

        token_path = os.path.join(self.tm._cache_dir, "token.json")
        self.assertTrue(os.path.exists(token_path))
        st = os.lstat(token_path)
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertFalse(stat.S_ISLNK(st.st_mode))
        self.assertEqual(st.st_mode & 0o777, 0o600)
        self.assertEqual(st.st_uid, os.getuid())

        # Verify load retrieves it
        loaded = self.tm.load()
        self.assertEqual(loaded, token)

    def test_load_rejects_symlink(self):
        """Item 2: Token loading refuses to follow symlinks (O_NOFOLLOW)."""
        os.makedirs(self.tm._cache_dir, mode=0o700, exist_ok=True)
        target = os.path.join(self.td.name, "target.txt")
        with open(target, "w") as f:
            f.write(json.dumps({"access_token": "leaked_token"}))

        symlink_path = os.path.join(self.tm._cache_dir, "token.json")
        os.symlink(target, symlink_path)

        # Loading must refuse to follow symlink
        self.assertIsNone(self.tm.load())

    def test_load_rejects_oversized_file(self):
        """Item 2: Token loading bounds input size."""
        os.makedirs(self.tm._cache_dir, mode=0o700, exist_ok=True)
        token_path = os.path.join(self.tm._cache_dir, "token.json")
        with open(token_path, "w") as f:
            f.write("A" * (MAX_TOKEN_FILE_SIZE + 100))

        self.assertIsNone(self.tm.load())

    def test_clear_removes_token(self):
        """Item 2: Clear safely unlinks token file."""
        self.tm.save("some_token")
        self.assertIsNotNone(self.tm.load())
        self.tm.clear()
        self.assertIsNone(self.tm.load())

    def test_exchange_code_input_validation(self):
        """Item 4: Exchange code rejects invalid input format."""
        with self.assertRaises(ValueError):
            TokenManager.exchange_code("")
        with self.assertRaises(ValueError):
            TokenManager.exchange_code("code with spaces")
        with self.assertRaises(ValueError):
            TokenManager.exchange_code("a" * 300)

    def test_exchange_code_byte_ceiling_and_redirect_handling(self):
        """Item 4: Strict byte ceiling, redirect rejection, and HTTPS origin check."""
        class MockServer(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://evil.com/token")
                    self.end_headers()
                elif self.path == "/huge":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"access_token": "' + b'x' * (MAX_HTTP_RESPONSE_BYTES + 50) + b'"}')
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"access_token": "valid_token"}).encode())

        # 1. Test untrusted origin rejection (http scheme and untrusted host)
        server = http.server.HTTPServer(("127.0.0.1", 0), MockServer)
        port = server.server_port
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            with patch("discord_bridge.TOKEN_EXCHANGE_URL", f"http://127.0.0.1:{port}/redirect"):
                with self.assertRaises(RuntimeError) as ctx:
                    TokenManager.exchange_code("valid_code_123")
                self.assertIn("Token exchange failed", str(ctx.exception))

            with patch("discord_bridge.TOKEN_EXCHANGE_URL", f"http://127.0.0.1:{port}/valid"):
                with self.assertRaises(RuntimeError) as ctx:
                    TokenManager.exchange_code("valid_code_123")
                self.assertIn("Insecure final scheme", str(ctx.exception))
        finally:
            server.shutdown()

        # 2. Test huge response ceiling rejection
        class DummyResp:
            def __init__(self, data):
                self.data = data
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def geturl(self):
                return "https://streamkit.discord.com/overlay/token"
            def read(self, n):
                return self.data[:n]

        huge_data = b'{"access_token": "' + b'x' * (MAX_HTTP_RESPONSE_BYTES + 50) + b'"}'
        with patch("urllib.request.OpenerDirector.open", return_value=DummyResp(huge_data)):
            with self.assertRaises(RuntimeError) as ctx:
                TokenManager.exchange_code("valid_code_123")
            self.assertIn("OAuth response exceeded maximum byte ceiling", str(ctx.exception))

        # 3. Test valid token extraction
        valid_data = json.dumps({"access_token": "valid_token_abc"}).encode()
        with patch("urllib.request.OpenerDirector.open", return_value=DummyResp(valid_data)):
            token = TokenManager.exchange_code("valid_code_123")
            self.assertEqual(token, "valid_token_abc")


class TestPIDManagerSecurity(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.runtime_dir = self.td.name

    def tearDown(self):
        self.td.cleanup()

    def test_write_and_remove_pid_record(self):
        """Item 3: Secure PID record creation and deterministic cleanup."""
        with patch("discord_bridge.get_verified_runtime_dir", return_value=self.runtime_dir):
            pid_file = PIDManager.write_pid()
            self.assertTrue(os.path.exists(pid_file))

            # Check permissions and ownership
            st = os.lstat(pid_file)
            self.assertTrue(stat.S_ISREG(st.st_mode))
            self.assertEqual(st.st_mode & 0o777, 0o600)
            self.assertEqual(st.st_uid, os.getuid())

            # Read record contents
            with open(pid_file, "r") as f:
                record = json.load(f)
            self.assertEqual(record["pid"], os.getpid())
            self.assertEqual(record["uid"], os.getuid())
            self.assertGreater(record["starttime"], 0)
            self.assertEqual(record["comm"], "discord_bridge.py")

            # Remove PID
            PIDManager.remove_pid()
            self.assertFalse(os.path.exists(pid_file))

    def test_signal_bridge_validates_identity_and_rejects_stale_or_fake(self):
        """Item 3: Validate PID record against live process and reject PID reuse/fakes."""
        with patch("discord_bridge.get_verified_runtime_dir", return_value=self.runtime_dir):
            # 1. Non-existent PID in record
            fake_record = {
                "pid": 99999999,
                "uid": os.getuid(),
                "starttime": 12345,
                "comm": "discord_bridge.py"
            }
            pid_file = os.path.join(self.runtime_dir, PIDManager.PID_FILENAME)
            with open(pid_file, "w") as f:
                json.dump(fake_record, f)

            # Signal attempt should fail safely and remove stale file
            result = PIDManager.signal_bridge(signal.SIGUSR1)
            self.assertFalse(result)
            self.assertFalse(os.path.exists(pid_file), "Stale PID file must be cleaned up")

            # 2. Valid PID but wrong starttime (PID reuse simulation)
            fake_record = {
                "pid": os.getpid(),
                "uid": os.getuid(),
                "starttime": 1,  # wrong starttime
                "comm": "discord_bridge.py"
            }
            with open(pid_file, "w") as f:
                json.dump(fake_record, f)

            result = PIDManager.signal_bridge(signal.SIGUSR1)
            self.assertFalse(result)


class TestBridgeControl(unittest.IsolatedAsyncioTestCase):
    async def test_toggle_mute_and_deafen_logic(self):
        """Item 3: Verify toggle logic sends correct SET_VOICE_SETTINGS commands."""
        bridge = DiscordBridge()
        mock_writer = unittest.mock.MagicMock()
        mock_writer.is_closing.return_value = False
        bridge.discord.writer = mock_writer
        sent_cmds = []

        async def mock_send_cmd(cmd, args=None):
            sent_cmds.append((cmd, args))

        bridge._send_cmd = mock_send_cmd

        # When deafened, toggle_mute should undeafen and unmute
        bridge.settings["deaf"] = True
        bridge.settings["mute"] = True
        bridge.toggle_mute()
        await asyncio.sleep(0.01)
        self.assertEqual(sent_cmds[-1], ("SET_VOICE_SETTINGS", {"deaf": False, "mute": False}))

        # When not deafened, toggle_mute should toggle mute
        bridge.settings["deaf"] = False
        bridge.settings["mute"] = False
        bridge.toggle_mute()
        await asyncio.sleep(0.01)
        self.assertEqual(sent_cmds[-1], ("SET_VOICE_SETTINGS", {"mute": True}))

        # Toggle deafen
        bridge.settings["deaf"] = False
        bridge.toggle_deafen()
        await asyncio.sleep(0.01)
        self.assertEqual(sent_cmds[-1], ("SET_VOICE_SETTINGS", {"deaf": True}))

    async def test_stdin_commands_processing(self):
        """Item 3: Verify _stdin_loop processes toggle_mute and toggle_deafen commands."""
        bridge = DiscordBridge()
        called = []
        bridge.toggle_mute = lambda: called.append("mute")
        bridge.toggle_deafen = lambda: called.append("deafen")

        # Simulate StreamReader
        reader = asyncio.StreamReader()
        reader.feed_data(b"toggle_mute\ntoggle_deafen\n")
        reader.feed_eof()

        loop = asyncio.get_running_loop()
        with patch.object(loop, "connect_read_pipe", side_effect=lambda factory, pipe: (unittest.mock.MagicMock(), None)):
            with patch("asyncio.StreamReader", return_value=reader):
                task = asyncio.create_task(bridge._stdin_loop())
                await asyncio.sleep(0.05)
                bridge._shutdown_event.set()
                await task

        self.assertIn("mute", called)
        self.assertIn("deafen", called)

    def test_signal_bridge_valid_process(self):
        """Item 3: Test signalling when live process record matches."""
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.Popen(["python3", "-c", "import time; time.sleep(10)"])
            try:
                record = {
                    "pid": proc.pid,
                    "uid": os.getuid(),
                    "starttime": PIDManager.get_process_starttime(proc.pid),
                    "comm": "discord_bridge.py"
                }
                with patch("discord_bridge.get_verified_runtime_dir", return_value=td):
                    pid_path = os.path.join(td, PIDManager.PID_FILENAME)
                    with open(pid_path, "w") as f:
                        json.dump(record, f)

                    orig_open = open
                    def fake_open(file, *args, **kwargs):
                        if str(file).endswith("/cmdline"):
                            import io
                            return io.BytesIO(b"python3\x00discord_bridge.py")
                        return orig_open(file, *args, **kwargs)

                    with patch("builtins.open", side_effect=fake_open):
                        success = PIDManager.signal_bridge(signal.SIGTERM)
                        self.assertTrue(success)
            finally:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    unittest.main()
