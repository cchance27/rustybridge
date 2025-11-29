window.initRustyBridgeTerminal = async function (terminalId, options) {
    try {
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

        term.write('Loading Session...\r\n');
        console.log('Terminal initialized successfully:', terminalId);
    } catch (err) {
        console.error('Failed to initialize terminal:', err);
    }
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
