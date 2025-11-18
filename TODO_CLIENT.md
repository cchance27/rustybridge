# Client Parity Plan (rb vs OpenSSH/PuTTY)

This doc tracks what the `rb` client already matches and what remains to close the gap with common OpenSSH/PuTTY workflows.

## Parity Overview

- Authentication
  - Supported: password, public‑key, OpenSSH certs (KEY=CERT), keyboard‑interactive, ssh‑agent auth.
  - Missing: GSSAPI/Kerberos, host‑based auth.
- Transport/crypto
  - Supported: modern defaults with opt‑in legacy suites, configurable rekey time/bytes, optional compression.
  - Missing: ControlMaster/connection reuse.
- Host keys
  - Supported: known‑hosts equivalent backed by SQLite; accept once/store/replace flows.
- Shell/PTY/signals
  - Supported: interactive shell with PTY modes, window change, signal mapping, newline mapping, optional local echo.
- Agent forwarding
  - Supported on Unix via `SSH_AUTH_SOCK`.
  - Missing platform features on Windows (Pageant/named pipes).

## Forwarding & Subsystems

- Local/remote TCP (-L/-R): implemented (register/cancel flows work).
- Dynamic SOCKS (-D): implemented (no‑auth), parity with `ssh -D`.
- Unix sockets: local/remote streamlocal (Unix) implemented.
- Env/locale propagation: `SendEnv` + locale modes (none/lang/all) via per‑channel `setenv`.
- Subsystems: `--subsystem` sends `channel.request_subsystem()` and wires stdio.
  - Note: sftp transport works; a user‑facing sftp UI remains a separate task.

## Escape Sequences (Interactive)

- Enter + `~` opens menu with colored `[rustybridge]` tag + prompt.
- Supported: `~.` disconnect, `~R` rekey, `~V/~v` change verbosity, `~#` list forwards, `~~` literal `~`, `~^Z` suspend (Unix), `~&` detach stdin (reattach with `SIGUSR1 <pid>`).
- Differences vs OpenSSH:
  - `~&` backgrounds until cleanup in OpenSSH (no reattach). We add reattach via signal (useful, but not identical).
  - `~B` (BREAK) not implemented; OpenSSH can send a break request.
  - `~C` (add/cancel forwards live) not implemented.

## Platform Notes

- Windows parity gaps: agent forwarding (Pageant), named‑pipe alternatives for streamlocal; Unix‑only features are unavailable.
- X11 forwarding unimplemented (flags are guarded and error out clearly).

## Feature Parity Checklist

- Auth: password/PK/cert/KBDINT/agent ✅ | GSSAPI/host‑based ❌
- Rekey/compression/keepalive ✅
- Host key mgmt (accept/store/replace) ✅
- -L/-R/-D ✅ | Unix sockets (Unix) ✅
- Env/locale forwarding ✅
- Subsystem channel open ✅ (sftp UX ❌)
- Escape menu + core escapes ✅ | `~C` add/cancel ❌ | `~B` BREAK ❌
- X11 ❌
- ControlMaster/connection reuse ❌
- ProxyJump/ProxyCommand ❌
- Windows agent forwarding/unix features ❌

## Recommended Next Steps

1) BREAK support (`~B`)
   - Add client request for RFC 4254 §6.7 “break” (upstream or local extension in russh).
  
2) Detach/reattach ergonomics
   - Ensure resume‑from‑suspend reliably places parser at line start across terminals.

3) Live forward management (`~C` parity)
   - Add escape “config mode” to add/cancel `-L/-R` forwards at runtime.
   - Extend `ForwardingManager` to spawn/cancel listeners and register/unregister remote forwards.
   - Consider migration of ~ migration to a proper TUI, maybe we can second screen over to a nice TUI for the escape menu selection, as well as managing forwards online, and on exit/suspend/etc just switch back to original screen view?

4) Connection multiplexing & proxies
   - ControlMaster/connection reuse (Unix domain control sockets).
   - `ProxyJump` / `ProxyCommand` support for common enterprise flows.

5) Windows parity
   - Pageant support for agent forwarding.
   - Named‑pipe equivalent for streamlocal forwards or document limitations.

6) Config file interop
   - Optional OpenSSH‑style config parsing for User/Port/IdentityFile/ProxyJump/LocalForward/etc.

7) X11 forwarding
   - Detect DISPLAY, generate MIT‑MAGIC‑COOKIE, issue `x11-req`, and proxy inbound x11 channels.

8) SFTP user experience
   - Provide a minimal sftp client UX (or integrate with an external `sftp` binary using our session) so `--subsystem sftp` is fully usable.
