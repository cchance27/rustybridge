Based on OpenSSH

# 1. Overall Model: *Escape Sequences Are Client-Side Control Signals*

OpenSSH escape sequences are **purely client-side**, intercepted **before** the user input stream is forwarded to the remote PTY or channel.

Key rules:

1. Escapes are recognized **only when the input buffer is in “line start” state**, meaning:

   * Just after a newline (`\n` or `\r`), or
   * At the start of the session.
2. The first character must be the configured escape (default `~`).
3. The next character determines the action.
4. To send a literal `~`, type `~~`.

This logic occurs in `ssh_input.c` + `clientloop.c` before any input is written into the channel.

**For your Rust client:**
You need a small state machine sitting between stdin → channel stdin.
OpenSSH implements this as:

```
if (last_was_newline) {
    if (ch == escape_char) -> enter_escape_state
}
if in_escape_state: evaluate next char
else: normal input
```

---

# 2. `~.`  — Terminate connection (hard disconnect)

### What it does:

* Immediately closes the SSH connection, bypassing remote shutdown.
* Tears down all multiplexed sessions (if in ControlMaster).

### How OpenSSH does it:

* Calls `fatal()` then `client_terminate()`.
* Sends nothing to the server.
* Drops all channels and the transport.

**Rust client implementation note:**
You literally **abort the transport**:

* Close all channels.
* Close the TCP socket.
* Stop event loops.

---

# 3. `~B` — Send BREAK to remote

### What it does:

A BREAK is a *special out-of-band serial-line signal* historically used to interrupt bootloaders, modems, routers, etc.

SSH supports BREAK via:

* SSH_MSG_CHANNEL_REQUEST `"break"` with a duration (e.g. 0ms).

RFC 4254, section 6.7.

### In OpenSSH:

```
channel_request(c, "break", 0, &duration)
```

### When does this do anything?

* If the remote server forwards BREAK to a serial console, e.g.:

  * Cisco routers
  * Linux serial consoles
  * VMs with serial debugging

**Rust client implementation:**

* Implement channel request type `"break"`.
* Duration can be 0.
* Most servers will ignore it; that is fine.

---

# 4. `~R` — Rekey (trigger key exchange / KEX)

### Purpose:

Forces the client to request a new KEX handshake outside of normal rekey intervals.

OpenSSH:

* Sets a flag `need_rekeying = 1`.
* Client loop triggers SSH2 key re-exchange:

  * Sends `SSH2_MSG_KEXINIT`.
  * Performs full DH/ECDH/ECDH or PQ hybrid, depending on algorithms.

**Rust client implementation:**

* Trigger your russh KEX state machine.
* Most libraries already allow “start a new rekey request”.

**Important:**
This is the only escape that modifies the SSH *transport layer* rather than channels.

---

# 5. `~V` / `~v` — Change local client verbosity

### What it does:

* Adjusts the log level printed by the client itself.
* Does *not* affect server logs or remote log level.

OpenSSH:

```
LogLevel += 1   (for V)
LogLevel -= 1   (for v)
```

**Rust implementation:**
Just adjust your internal logging filter for the client, not the session.

---

# 6. `~^Z` — Suspend ssh (SIGSTOP, Unix only)

### What it does:

Sends SIGSTOP to the ssh process.

Effect:

* SSH goes to background, “frozen”.
* User is returned to local shell.
* `fg` resumes.

**Rust implementation difficulty:**
You must:

* On Unix: send `libc::kill(getpid(), SIGSTOP)`.
* On Windows: not supported (OpenSSH ignores it).

---

# 7. `~&` — Background ssh (*while it waits for channels to close*)

This is *not* the same as `~^Z`.

### What it does:

* If user has typed `~&` **after closing the last channel but before the underlying TCP has fully drained**, ssh will:

  * Detach from stdin.
  * Continue running *in the background*.
  * Wait for pending forwarded ports, exit-status messages, etc.

### Why?

Rare case:

* User ended the session (e.g., typed `exit`), but scp or forwarding cleanup still needs to happen.
* Instead of waiting, user sends this escape to let SSH finish without blocking the terminal.

**Rust implementation:**

* Detach reading from stdin.
* Keep event loop running until:

  * All channels are closed,
  * All forwarded connections finish,
  * Transport shuts down.
* Daemonize? No. Just drop stdin and return control to user’s shell.

---

# 8. `~#` — List forwarded connections

### Displays:

* Active port forwards.
* Connection information (source, target, status).

OpenSSH prints something like:

```
The following connections are open:
  #1 client 127.0.0.1 port 54321 type direct-tcpip
  #2 client 127.0.0.1 port 54322 type forward
```

### Rust implementation:

Internally, you track:

* Each active forwarded channel.
* Its source address.
* Target address.
* Direction (`direct-tcpip` vs `forwarded-tcpip`).

When user types `~#`, print them to stdout.

---

# 9. `~~` — Send literal escape character

### Logic:

If user presses:

```
~~
```

the first `~` enters escape mode,
the second `~` escapes the escape, writing a literal `~` to remote.

**Rust implementation:**
State machine:

* If in escape state and next char == escape: send a single `~` to remote and exit escape state.

---

# 10. Summary Table (Implementation View)

| Escape    | Client Action                             | Transport Layer? | Channel Layer?         |
| --------- | ----------------------------------------- | ---------------- | ---------------------- |
| `~.`      | Immediate disconnect                      | Yes              | Yes                    |
| `~B`      | Send BREAK request                        | Yes              | Affects active channel |
| `~R`      | Trigger KEX rekey                         | Yes              | No                     |
| `~v` `~V` | Adjust local verbosity                    | No               | No                     |
| `~^Z`     | SIGSTOP process                           | No               | No                     |
| `~&`      | Background client while finishing cleanup | Yes              | Yes                    |
| `~#`      | List forwarded connections                | No               | Yes                    |
| `~~`      | Send literal `~`                          | No               | Yes                    |

---

# 11. Full Minimal Implementation Plan for Your Rust SSH Client

## State machine for escape parsing

* Track `last_char_was_newline`
* Track `escape_mode`
* Escape character configurable (default `~`)

## Add handlers for each escape:

* `.terminate()` → close session + TCP.
* `.send_break()` → channel request `"break"`.
* `.request_rekey()` → invoke transport-level KEX logic.
* `.adjust_verbosity()` → modify log filter.
* `.sigstop()` → Unix only; call `kill(SIGSTOP)`.
* `.background()` → detach stdin, continue event loop.
* `.list_forwarded()` → print connection table.
* `.literal_escape()` → send `~` to remote.

## Consider platform compatibility

* `~^Z` only on Unix.
* Some features irrelevant when no PTY is used (scp, sftp).
