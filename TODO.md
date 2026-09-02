## Security problems with this plugin:

1. [x] **The local IPC frame length is trusted before allocation.**
   - **Fixed**:
     - `_candidate_paths()` validates parent directories: ensures they are owned by `os.getuid()`, have non-permissive modes (`st_mode & 0o022 == 0`), and are not symlinks. Unsafe fallback paths like raw `/tmp` are strictly rejected.
     - Each candidate socket path is checked via `os.lstat()` to ensure it is a socket (`S_ISSOCK`), owned by the current user, and not a symlink.
     - Connected UNIX sockets verify peer identity using `SO_PEERCRED`: immediately closes the connection if `peer_uid != os.getuid()` before transmitting any handshake or cached credentials.
     - Enforces `MAX_FRAME_SIZE = 64 * 1024` ceiling before allocating or reading frame payloads. Validates opcode and enforces strict JSON dict schema.

2. [x] **OAuth token persistence follows predictable paths unsafely.**
   - **Fixed**:
     - `TokenManager` enforces a verified, privatized cache directory chain (`verify_private_dir` with mode `0700` and `O_NOFOLLOW`).
     - `load()` uses `O_NOFOLLOW`, verifies regular file status and user ownership, tightens permissions to `0600` if needed, enforces a bounded read ceiling (`MAX_TOKEN_FILE_SIZE = 8 * 1024`), and validates token structure.
     - `save()` writes to an exclusive random mode-0600 temp file (`O_CREAT | O_EXCL | O_NOFOLLOW`), explicitly tightens permissions with `os.fchmod(tmp_fd, 0o600)`, fsyncs, and executes atomic descriptor-relative replacement (`os.replace` with `src_dir_fd` and `dst_dir_fd`). Cleans up temp files on error.

3. [x] **The PID control path is not identity-bound.**
   - **Fixed**:
     - `Widget.qml` completely eliminates shell execution and file reads, calling `discordService.toggleMute()` / `discordService.toggleDeafen()` to communicate directly with the daemon process over stdin IPC (`stdinEnabled: true`).
     - Fallback runtime directories (`/tmp/opoii_discord_<uid>`) are strictly verified for user ownership, directory type, no symlinks, and mode `0700`.
     - `PIDManager.write_pid()` writes an identity-bound JSON PID record containing `pid`, `uid`, `starttime` (from `/proc/[pid]/stat`), and executable identity (`comm`). Writes with mode `0600` and atomic descriptor-relative replace.
     - Deterministically removes PID files upon clean exit, shutdown signals, and via `atexit`.
     - For external hotkeys, `python3 discord_bridge.py --toggle-mute` and `--toggle-deafen` validate the target process identity against `/proc/[pid]/status` (UID match), `/proc/[pid]/stat` (start time match to prevent PID reuse attacks), and `/proc/[pid]/cmdline` before delivering signals. Stale PID files are cleaned up.

4. [x] **OAuth exchange input is unbounded and redirect handling is unrestricted.**
   - **Fixed**:
     - Input code is strictly validated against a safe ASCII format and bounded length (`1 <= len(code) <= 256`).
     - Strict response byte ceiling (`MAX_HTTP_RESPONSE_BYTES = 32 * 1024`) enforces bounds during token reading.
     - Redirect handling is restricted using a custom `StrictRedirectHandler` (`max_redirects = 0`) that disallows redirects.
     - Validates final response URL to guarantee HTTPS scheme and expected origin (`streamkit.discord.com`).
     - Bounded overall async execution deadline (`OPERATION_TIMEOUT = 10.0`s).

5. [x] **Lifecycle bounds are incomplete.**
   - **Fixed**:
     - Added strict timeouts to connection (`CONNECT_TIMEOUT = 2.0`s) and handshake (`HANDSHAKE_TIMEOUT = 5.0`s).
     - Read loop incorporates an idle ping interval (`IDLE_PING_INTERVAL = 30.0`s) with active `OP_PING` heartbeat probes and a 5-second pong deadline (`PING_RESPONSE_TIMEOUT = 5.0`s) to terminate unresponsive or false sockets.
     - Deterministic cancellation and shutdown handlers cleanly release resources and unlink the PID file.

