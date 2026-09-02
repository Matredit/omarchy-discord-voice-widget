## Security fixes applied to address @original_review.md:

1. [x] **The local IPC frame length is trusted before allocation.**
   - **Fixed**:
     - `_candidate_paths()` discovers candidate paths solely in verified private directories (`XDG_RUNTIME_DIR`, Flatpak, Snap). Unsafe fallback paths such as raw `/tmp` are strictly rejected.
     - Each candidate directory and its full directory chain is verified using descriptor-relative `O_NOFOLLOW` checks (`verify_private_dir`), ensuring ownership by `os.getuid()`, non-permissive modes, and absence of symlinks.
     - Sockets are statted with `os.stat(..., dir_fd=dir_fd, follow_symlinks=False)` and `os.lstat()` to ensure they are true UNIX sockets (`S_ISSOCK`), owned by the current UID, and not symlinks.
     - `SO_PEERCRED` checks `peer_uid == os.getuid()` and `peer_pid > 0` immediately upon connecting; connections to mismatched or invalid peers are rejected without transmitting data.
     - `MAX_FRAME_SIZE = 64 * 1024` (64 KiB) ceiling is strictly enforced before reading or allocating any frame payload buffer.
     - `validate_frame_payload()` validates opcode and enforces strict bounds on frame schema fields (`cmd`, `evt`, `nonce`).
     - Nested dictionary helper `safe_dict()` prevents crashes on malformed or malicious payload structures.
     - **Handshake Verification & Token Protection**: `handshake()` validates that the response is an authentic Discord `OP_FRAME` `DISPATCH` event with `READY` status and configuration containing Discord endpoints (`cdn_host` or `api_endpoint`). If the endpoint fails to authenticate as Discord, handshake raises `ConnectionError`, preventing the cached OAuth token from ever being transmitted during `AUTHENTICATE`.

2. [x] **OAuth token persistence follows predictable paths unsafely.**
   - **Fixed**:
     - `verify_private_dir()` verifies the entire directory chain component-by-component starting from `/` with `O_NOFOLLOW` and `dir_fd`. It rejects intermediate symlinks, ensures ownership by current UID, privatizes user directories with mode `0700`, and verifies parent system directories are not world-writable without sticky bits.
     - `load()` opens `token.json` with `O_NOFOLLOW` relative to `dir_fd`, verifies regular file status (`S_ISREG`), verifies UID ownership, tightens permissions to `0600` if needed, enforces a bounded read ceiling (`MAX_TOKEN_FILE_SIZE = 8 * 1024`), and validates token structure and character charset (`[A-Za-z0-9_.-]+`).
     - `save()` checks if destination is a symlink and unlinks it descriptor-relatively, creates an exclusive random temp file (`.token_<hex>.tmp`) with `O_CREAT | O_EXCL | O_NOFOLLOW` mode `0600`, calls `fchmod(tmp_fd, 0o600)`, flushes via `os.fsync()`, and performs atomic descriptor-relative replacement (`os.replace` with `src_dir_fd` and `dst_dir_fd`). Mode `0600` is explicitly reapplied to the destination file.
     - Cleans up temporary files in `finally` upon any failure.

3. [x] **The PID control path is not identity-bound.**
   - **Fixed**:
     - `Widget.qml` completely eliminates shell execution, file reads, and PID signalling, communicating directly with the daemon process via `discordService.toggleMute()` / `toggleDeafen()` over stdin IPC (`stdinEnabled: true`).
     - `Service.qml` handles stdin IPC commands directly and validates state strings against an allowed whitelist (`tray`, `tray-connected`, `tray-muted`, `tray-deafened`, `tray-speaking`).
     - Fallback runtime directories (`/tmp/opoii_discord_<uid>`) are strictly verified for user ownership, directory type, no symlinks, and mode `0700` using directory chain verification.
     - `PIDManager.write_pid()` writes an identity-bound JSON PID record containing `pid`, `uid`, `starttime` (from `/proc/[pid]/stat`), and executable identity (`comm`). Writes with mode `0600` and atomic descriptor-relative replace.
     - Deterministically removes PID files upon clean exit, shutdown signals (`SIGTERM`, `SIGINT`, `SIGHUP`), and via `atexit`. `remove_pid()` verifies that the disk record still matches the current PID before unlinking.
     - For external hotkeys (`--toggle-mute`, `--toggle-deafen`), `PIDManager.signal_bridge()` rigorously validates the target process before signalling:
       - Confirms `starttime > 0` and matches live process `/proc/[pid]/stat` start time to prevent PID reuse attacks.
       - Confirms `/proc/[pid]/status` real UID matches current user.
       - Confirms `/proc/[pid]/cmdline` arguments contain `discord_bridge.py`.
       - Confirms `/proc/[pid]/exe` resolves to Python binary.
       - If the target process is dead or starttime mismatched, stale PID files are cleaned up safely.

4. [x] **OAuth exchange input is unbounded and redirect handling is unrestricted.**
   - **Fixed**:
     - Authorization code input is strictly bounded (`1 <= len(code) <= 256`) and validated against ASCII charset `^[A-Za-z0-9_.\-]+$`.
     - Initial URL and final response URL are validated to ensure HTTPS scheme and expected origin (`streamkit.discord.com`).
     - Redirect handling uses custom `StrictRedirectHandler` enforcing `MAX_REDIRECTS = 3`. Each redirect target is resolved with `urllib.parse.urljoin`, and validated for HTTPS scheme and expected origin. Responses are explicitly closed to avoid resource leaks.
     - Strict response byte ceiling (`MAX_HTTP_RESPONSE_BYTES = 32 * 1024`) enforces bounds during token reading.
     - Overall execution deadline (`OAUTH_OVERALL_TIMEOUT = 10.0`s) is enforced using monotonic clock checks both synchronously and asynchronously in `asyncio.wait_for`.

5. [x] **Lifecycle bounds are incomplete.**
   - **Fixed**:
     - Bounded connection deadline (`CONNECT_TIMEOUT = 2.0`s).
     - Bounded handshake deadline (`HANDSHAKE_TIMEOUT = 5.0`s) and payload read deadline (`READ_PAYLOAD_TIMEOUT = 5.0`s).
     - Whole-connection initialization deadline (`CONNECTION_INIT_TIMEOUT = 15.0`s) bounds setup from connect through handshake, authenticate/authorize, and initial voice subscriptions.
     - Per-operation deadline (`OPERATION_TIMEOUT = 10.0`s): pending commands are tracked with monotonic timestamps and pruned if unanswered. Timed-out critical commands trigger connection reset.
     - Read loop incorporates an idle ping interval (`IDLE_PING_INTERVAL = 30.0`s) with active `OP_PING` heartbeat probes and a 5-second pong deadline (`PING_RESPONSE_TIMEOUT = 5.0`s) to terminate unresponsive or false sockets.
     - Deterministic cancellation and shutdown handlers cleanly release resources and unlink the PID file.


