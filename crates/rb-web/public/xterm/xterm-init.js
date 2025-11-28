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
                // Only fit if the container is visible and has dimensions
                if (container.clientWidth > 0 && container.clientHeight > 0) {
                    try {
                        console.log('ResizeObserver fitting terminal...');
                        fitAddon.fit();
                    } catch (e) {
                        console.warn('ResizeObserver failed to fit terminal:', e);
                    }
                }
            });
            resizeObserver.observe(container);
            
            // Store fitAddon on the terminal instance so we can access it later
            term._fitAddon = fitAddon;
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

// Function to write data to the terminal from Rust
window.writeToTerminal = function (terminalId, data) {
    const term = window.terminals[terminalId];
    if (term) {
        // data can be a UTF-8 string or raw bytes (Uint8Array)
        if (typeof data === 'string') {
            term.write(data);
            return;
        }

        if (data instanceof Uint8Array) {
            window._rbTextDecoder = window._rbTextDecoder || new TextDecoder('utf-8', { fatal: false });
            const decoded = window._rbTextDecoder.decode(data);
            term.write(decoded);
            return;
        }

        // Fallback for plain arrays or unexpected types
        if (Array.isArray(data)) {
            window._rbTextDecoder = window._rbTextDecoder || new TextDecoder('utf-8', { fatal: false });
            const decoded = window._rbTextDecoder.decode(new Uint8Array(data));
            term.write(decoded);
            return;
        }

        term.write(String(data));
    } else {
        console.warn(`writeToTerminal: Terminal ${terminalId} not found`);
    }
};

// Function to setup input handling to send data back to Rust
window.setupTerminalInput = function (terminalId, onDataCallback) {
    const term = window.terminals[terminalId];
    if (term) {
        if (term._inputDisposable) {
            term._inputDisposable.dispose();
        }
        term._inputDisposable = term.onData(data => {
            // Convert string to Uint8Array for consistency with Rust Vec<u8>
            const encoder = new TextEncoder();
            const bytes = encoder.encode(data);
            // Pass the data to the callback (which will be a Dioxus closure)
            // We need to pass it as an array or similar that Dioxus can handle
            // Dioxus closures usually expect JSON-serializable args or specific types.
            // For now, let's assume the callback handles the raw data or we pass it as array.
            // Actually, Dioxus eval closures might be tricky with binary data.
            // Let's pass it as an array of numbers.
            onDataCallback(Array.from(bytes));
        });
        console.log(`Input handling setup for terminal ${terminalId}`);
        return true;
    } else {
        console.warn(`setupTerminalInput: Terminal ${terminalId} not found`);
        return false;
    }
};

window.focusTerminal = function (terminalId) {
    const term = window.terminals[terminalId];
    if (term) {
        term.focus();
    } else {
        console.warn(`focusTerminal: Terminal ${terminalId} not found`);
    }
};

window.fitTerminal = function (terminalId) {
    const term = window.terminals[terminalId];
    if (term && term._fitAddon) {
        try {
            term._fitAddon.fit();
        } catch (e) {
            console.warn(`fitTerminal: Failed to fit terminal ${terminalId}`, e);
        }
    }
};

// Deprecated: attachWebSocketToTerminal is no longer used with Dioxus use_websocket
window.attachWebSocketToTerminal = async function (terminalId, websocketUrl, connectToken, onClose) {
    console.warn("attachWebSocketToTerminal is deprecated and should not be used.");
    return null;
}
