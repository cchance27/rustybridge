
// Initialize globals
window.terminals = window.terminals || {};

// Debounce helper to prevent spamming
window.debounce = (func, wait) => {
    let timeout;
    return function (...args) {
        const later = () => {
            clearTimeout(timeout);
            func.apply(this, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
};

window.initRustyBridgeTerminal = async (terminalId, options) => {
    try {
        const container = document.getElementById(terminalId);
        if (!container) {
            console.error('Terminal container not found:', terminalId);
            return;
        }

        if (container.dataset.initialized) return;
        container.dataset.initialized = "true";

        container.innerHTML = '';

        const termOptions = {
            cursorBlink: true,
            convertEol: true,
            fontFamily: 'Menlo, Monaco, "Courier New", monospace',
            fontSize: 14,
            theme: {
                background: '#1e1e1e',
                foreground: '#ffffff',
            },
        };

        // If explicit cols/rows were provided (e.g. from a recording),
        // include them; otherwise let xterm use its defaults.
        if (options && typeof options.cols === 'number' && options.cols > 0) {
            termOptions.cols = options.cols;
        }
        if (options && typeof options.rows === 'number' && options.rows > 0) {
            termOptions.rows = options.rows;
        }

        const term = new window.Terminal(termOptions);

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

        // If explicit cols/rows were provided and fit is disabled,
        // size the container based on the actual cell dimensions so
        // the terminal geometry matches the recording instead of the layout.
        if (options && typeof options.cols === 'number' && typeof options.rows === 'number' && !options.fit) {
            const setSize = () => {
                try {
                    const core = term._core;
                    const dims = core?._renderService?._dimensions;
                    if (dims?.actualCellWidth && dims.actualCellHeight) {
                        const width = dims.actualCellWidth * options.cols;
                        const height = dims.actualCellHeight * options.rows;
                        container.style.width = `${width}px`;
                        container.style.height = `${height}px`;
                        container.style.display = 'block';
                        return true;
                    }
                } catch (e) {
                    console.warn('Failed to apply fixed terminal size from recording:', e);
                }
                return false;
            };

            // Try immediately and then retry for a short period if needed
            if (!setSize()) {
                let attempts = 0;
                const interval = setInterval(() => {
                    attempts++;
                    if (setSize() || attempts > 20) { // Retry for up to ~400ms
                        clearInterval(interval);
                    }
                }, 20);
            }
        }

        if (fitAddon) {
            fitAddon.fit();

            // Use ResizeObserver to handle container resizing
            const debouncedFit = window.debounce(() => {
                // Only fit if the container is visible and has dimensions
                if (container.clientWidth > 0 && container.clientHeight > 0) {
                    try {
                        console.log('ResizeObserver fitting terminal...');
                        fitAddon.fit();
                    } catch (e) {
                        console.warn('ResizeObserver failed to fit terminal:', e);
                    }
                }
            }, 250); // 250ms debounce for layout fitting

            const resizeObserver = new ResizeObserver(() => {
                debouncedFit();
            });
            resizeObserver.observe(container);

            // Store fitAddon on the terminal instance so we can access it later
            term._fitAddon = fitAddon;
        }

        window.terminals[terminalId] = term;

        term.write('Loading Session...\r\n');
        console.log('Terminal initialized successfully:', terminalId);
    } catch (err) {
        console.error('Failed to initialize terminal:', err);
    }
}

// Function to write data to a terminal (called from Rust)
window.writeToTerminal = (terminalId, data) => {
    const term = window.terminals[terminalId];
    if (!term) {
        console.warn(`writeToTerminal: Terminal ${terminalId} not found`);
        return false;
    }

    // Handle string input
    if (typeof data === 'string') {
        term.write(data);
        return true;
    }

    if (data instanceof Uint8Array) {
        window._rbTextDecoder = window._rbTextDecoder || new TextDecoder('utf-8', { fatal: false });
        const decoded = window._rbTextDecoder.decode(data);
        term.write(decoded);
        return true;
    }

    // Fallback for plain arrays or unexpected types
    if (Array.isArray(data)) {
        window._rbTextDecoder = window._rbTextDecoder || new TextDecoder('utf-8', { fatal: false });
        const decoded = window._rbTextDecoder.decode(new Uint8Array(data));
        term.write(decoded);
        return true;
    }

    term.write(data);
    return true;
};

// Function to setup input handling to send data back to Rust
window.setupTerminalInput = (terminalId, onDataCallback) => {
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
        return true;
    }

    console.warn(`setupTerminalInput: Terminal ${terminalId} not found`);
    return false;
};

window.focusTerminal = (terminalId) => {
    const term = window.terminals[terminalId];
    if (term) {
        term.focus();
    } else {
        console.warn(`focusTerminal: Terminal ${terminalId} not found`);
    }
};

window.fitTerminal = (terminalId) => {
    const term = window.terminals[terminalId];
    if (term?._fitAddon) {
        try {
            term._fitAddon.fit();
        } catch (e) {
            console.warn(`fitTerminal: Failed to fit terminal ${terminalId}`, e);
        }
    }
};

// Function to get current terminal dimensions
window.getTerminalDimensions = (terminalId) => {
    const term = window.terminals[terminalId];
    if (term) {
        return {
            cols: term.cols,
            rows: term.rows
        };
    }
    return null;
};

// Function to setup resize handling to send dimensions back to Rust
window.setupTerminalResize = (terminalId, onResizeCallback) => {
    const term = window.terminals[terminalId];
    if (term) {
        if (term._resizeDisposable) {
            term._resizeDisposable.dispose();
        }

        // Debounce resize events by 250
        const debouncedResize = window.debounce((size) => {
            onResizeCallback({ cols: size.cols, rows: size.rows });
        }, 250);

        term._resizeDisposable = term.onResize(debouncedResize);
        console.log(`Resize handling setup for terminal ${terminalId} (debounced)`);
        return true;
    }

    console.warn(`setupTerminalResize: Terminal ${terminalId} not found`);
    return false;
};
