window.initRustyBridgeTerminal = async function (terminalId, options) {
    async function loadScript(src) {
        {
            if (document.querySelector(`script[src="${src}"]`)) return;
            return new Promise((resolve, reject) => {
                {
                    const script = document.createElement('script');
                    script.src = src;
                    script.onload = resolve;
                    script.onerror = reject;
                    document.head.appendChild(script);
                }
            });
        }
    }

    async function loadCss(href) {
        {
            if (document.querySelector(`link[href="${href}"]`)) return;
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = href;
            document.head.appendChild(link);
        }
    }

    try {
        await loadCss('/xterm/xterm.css');

        if (!window.Terminal) {
            await loadScript('/xterm/xterm.js');
            console.log("Loaded xterm")
        }

        if (options.fit && !window.FitAddon) {
            await loadScript('/xterm/addon-fit.js');
            console.log("Loaded fit addon")
        }

        if (options.web_links && !window.WebLinksAddon) {
            await loadScript('/xterm/addon-web-links.js');
            console.log("Loaded web links addon")
        }

        if (options.webgl && !window.WebglAddon) {
            await loadScript('/xterm/addon-webgl.js');
            console.log("Loaded webgl addon")
        }

        const container = document.getElementById(terminalId);
        if (!container) {
            console.error('Terminal container not found:', terminalId);
            return;
        }

        if (container.dataset.initialized) return;
        container.dataset.initialized = "true";

        container.innerHTML = '';

        const term = new window.Terminal({
            cursorBlink: true,
            convertEol: true,
            fontFamily: 'Menlo, Monaco, "Courier New", monospace',
            fontSize: 14,
            theme: {
                background: '#1e1e1e',
                foreground: '#ffffff',
            }
        });

        let fitAddon = null;
        if (options.fit && window.FitAddon) {
            fitAddon = new window.FitAddon.FitAddon();
            term.loadAddon(fitAddon);
        }

        if (options.web_links && window.WebLinksAddon) {
            term.loadAddon(new window.WebLinksAddon.WebLinksAddon());
        }

        if (options.webgl && window.WebglAddon) {
            const webglAddon = new window.WebglAddon.WebglAddon();
            webglAddon.onContextLoss(e => {
                webglAddon.dispose();
            });
            term.loadAddon(webglAddon);
        }

        term.open(container);

        if (fitAddon) {
            fitAddon.fit();

            // Use ResizeObserver to handle container resizing
            const resizeObserver = new ResizeObserver(() => {
                try {
                    console.log('ResizeObserver fitting terminal...');
                    fitAddon.fit();
                } catch (e) {
                    console.warn('ResizeObserver failed to fit terminal:', e);
                }
            });
            resizeObserver.observe(container);

            // Store observer to disconnect later if needed (though we don't have a cleanup hook here yet)
            // For now, this is attached to the DOM element's lifetime effectively
        }

        window.terminals = window.terminals || {};
        window.terminals[terminalId] = term;

        // term.onData handler removed to prevent double echo when AttachAddon is active.
        // The AttachAddon will handle input sending to the server.

        term.write('Welcome to RustyBridge Terminal\r\n');
        term.write('Type something to test echo...\r\n');

        console.log('Terminal initialized successfully:', terminalId);
    } catch (err) {
        console.error('Failed to initialize terminal:', err);
    }
}

// Function to attach a WebSocket to a terminal for SSH connections
// connectToken is used to prevent stale async tasks from overwriting newer selections
window.attachWebSocketToTerminal = async function (terminalId, websocketUrl, connectToken, onClose) {
    try {
        const term = window.terminals[terminalId];
        if (!term) {
            console.error('Terminal not found:', terminalId);
            return null;
        }

        const isStale = () => term.activeSshToken !== connectToken;

        console.log('[rb-web] attach called', { terminalId, websocketUrl, connectToken, active: term.activeSshToken });

        // Create WebSocket connection
        console.log('[rb-web] creating WebSocket', websocketUrl);
        const socket = new WebSocket(websocketUrl);

        // Wait for the socket to open before attaching, with a timeout so we don't hang forever
        await new Promise((resolve, reject) => {
            const timeoutMs = 8000;
            const timeout = setTimeout(() => {
                if (!isStale()) {
                    console.warn('WebSocket open timed out, closing socket');
                }
                socket.close();
                reject(new Error('WebSocket open timed out'));
            }, timeoutMs);

            socket.onopen = () => {
                clearTimeout(timeout);
                if (isStale()) {
                    console.log('[rb-web] socket open but stale token, closing');
                    socket.close();
                    return;
                }
                console.log('WebSocket connected for terminal:', terminalId);
                term.write('\r\n\x1b[32mConnected to SSH session\x1b[0m\r\n');
                resolve();
            };

            socket.onerror = (error) => {
                clearTimeout(timeout);
                if (isStale()) {
                    console.log('[rb-web] socket error but stale token, closing');
                    socket.close();
                    return;
                }
                console.error('WebSocket error:', error);
                term.write('\r\n\x1b[31mWebSocket connection error\x1b[0m\r\n');
                reject(error);
            };

            socket.onclose = (event) => {
                clearTimeout(timeout);
                if (isStale()) {
                    console.log('[rb-web] socket close but stale token');
                    return;
                }
                if (event.code !== 1000) {
                    console.warn('WebSocket closed before open/attach:', event.code, event.reason);
                    reject(new Error('WebSocket closed during connect'));
                }
            };
        });

        socket.onclose = () => {
            if (isStale()) {
                return;
            }
            console.log('WebSocket closed for terminal:', terminalId);
            term.write('\r\n\x1b[33mConnection closed\x1b[0m\r\n');
            // Notify Rust side that connection closed
            if (onClose) {
                onClose();
            }
        };

        // Load attach addon if not already loaded
        if (!window.AttachAddon) {
            await loadScript('/xterm/addon-attach.js');
            console.log("Loaded attach addon");
        }

        if (isStale()) {
            socket.close();
            return null;
        }

        // Attach the WebSocket to the terminal (socket is now open)
        const attachAddon = new window.AttachAddon.AttachAddon(socket);
        term.loadAddon(attachAddon);

        // Disable local echo - the SSH server will echo back
        term.options.disableStdin = false; // Keep stdin enabled

        // Clear the welcome message
        term.clear();

        if (isStale()) {
            attachAddon.dispose();
            socket.close();
            return null;
        }

        return {
            socket: socket,
            addon: attachAddon,
            disconnect: () => {
                attachAddon.dispose();
                socket.close();
            }
        };
    } catch (err) {
        console.error('Failed to attach WebSocket:', err);
        const term = window.terminals[terminalId];
        if (term) {
            term.write('\r\n\x1b[31mFailed to connect: ' + err.message + '\x1b[0m\r\n');
        }
        return null;
    }
}

// Helper function for loadScript (needs to be accessible)
async function loadScript(src) {
    if (document.querySelector(`script[src="${src}"]`)) return;
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = src;
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
}
