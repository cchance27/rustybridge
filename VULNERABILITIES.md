# Known Vulnerabilities & Security Risks

This document outlines the known security vulnerabilities and risks associated with the `rustybridge` project. We believe in being transparent about security and providing users with the information they need to operate this software safely.

## Guiding Principle: Explicit Insecurity

This project is designed to interact with legacy hardware that may not support modern, secure cryptographic standards. To enable this, we provide options to downgrade security settings.

**This functionality is inherently dangerous and is disabled by default.**

Insecure cryptographic suites are *only* enabled when a user explicitly requests them via a command-line flag on the client or a server-side configuration option. Our philosophy is that users must consciously opt-in to a less secure mode.

---

## 1. RUSTSEC-2023-0071: `rsa` Crate Timing Attack (Marvin Attack)

- **ID:** RUSTSEC-2023-0071 / CVE-2023-49092
- **Severity:** Medium
- **Component:** `rsa` crate (a dependency)
- **Description:** The version of the `rsa` crate used in this project is vulnerable to the "Marvin Attack." This is a timing side-channel vulnerability where an attacker who can observe network timing differences during RSA decryption could potentially recover the private key.

### How It Is Triggered

This vulnerability is only exposed when RSA-based algorithms are in use. In `rustybridge`, RSA and other weak algorithms are only enabled when an insecure mode is explicitly activated for outbound connections.

- **On the Client (`rb`) [outbound]:**
  - By using the `--insecure` command-line flag.
  - This enables a legacy suite of algorithms, including `rsa-sha1`, which uses the vulnerable `rsa` crate functionality.

- **On the Server (`rb-server` as a Jump Host) [outbound to relay targets]:**
  - By setting the `insecure=true` option on a specific relay host.
  - Example: `rb-server hosts options set my-legacy-host insecure true`
  - When the server connects to `my-legacy-host`, it will use the same legacy suite, thus exposing the server's outbound connection to this vulnerability.

### Mitigation

**Do not use the `--insecure` flag or the `insecure=true` server option unless it is absolutely necessary to connect to a legacy device and you are on a completely trusted network where network traffic cannot be monitored by malicious actors.**

By default, `rustybridge` uses a modern, secure set of algorithms for all connections, and `rb-server` always uses secure defaults for inbound client connections.

---

## 2. General Use of Weak Cryptographic Algorithms

In addition to the specific `rsa` vulnerability, the insecure mode enables other algorithms that are considered weak or broken by modern standards.

- **Algorithms Enabled in Insecure Mode:**
  - **Key Exchange:** `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`
  - **Public Key:** `ssh-dss` (DSA), `ssh-rsa` (with SHA-1)
  - **Ciphers:** `3des-cbc`, `aes128-cbc`
  - **MACs:** `hmac-sha1`

- **Risks:** These algorithms are vulnerable to various attacks that could allow an attacker to decrypt traffic or compromise the integrity of the connection.

### How It Is Triggered

This is triggered in the exact same way as the RSA vulnerability, and only for outbound connections:

- **Client (`rb`) outbound:** Use of the `--insecure` flag.
- **Server (`rb-server`) outbound to relay target:** Use of the `insecure=true` option for that host.

Inbound connections to `rb-server` are always negotiated with secure defaults.

### Mitigation

The mitigation is the same: **Avoid using insecure modes.** The risk of using these algorithms is significant. Only use them as a last resort for hardware that has no upgrade path, and only on trusted networks.
