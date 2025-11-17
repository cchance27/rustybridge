# Client Todo

- [ ] Escape sequences: OpenSSH supports ~. or ~C escapes for local control, PuTTY offers a settings UI mid-session. We currently send stdin verbatim, so there’s no way to hang up or tweak port forwards locally.
- [ ] Forwarding features: No X11, TCP, or Unix socket forwarding; no subsystem requests (sftp), no env/locale propagation.
- [ ] Session management: No escape to background/tmux-like reconnection, no connection reuse (ControlMaster), no ProxyCommand integration.