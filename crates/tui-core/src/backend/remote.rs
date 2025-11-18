//! Ratatui backend plumbing that knows how to emit escape sequences over russh channels.
//!
//! This is migrated from server-core/src/remote_backend.rs

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use ratatui::{
    backend::{Backend, ClearType, CrosstermBackend, WindowSize},
    layout::{Position, Rect, Size},
};

/// Owns a [`Terminal`] configured with the custom backend that writes into an in-memory buffer.
///
/// The handler renders into this terminal and later drains the bytes to forward over SSH.
pub struct ServerTerminal {
    terminal: ratatui::Terminal<RemoteBackend>,
}

impl ServerTerminal {
    /// Create a new terminal tied to a fixed area. The backend can be resized later.
    pub fn new(area: Rect) -> io::Result<Self> {
        let backend = RemoteBackend::new(area);
        let terminal = ratatui::Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    /// Ensure the terminal's viewport matches the remote PTY dimensions.
    pub fn ensure_size(&mut self, area: Rect) -> io::Result<()> {
        if self.terminal.backend().area() != area {
            self.terminal.backend_mut().set_size(area);
            self.terminal.resize(area)?;
        }
        Ok(())
    }

    /// Render a frame using ratatui's differential draw API.
    pub fn draw<F>(&mut self, f: F) -> io::Result<()>
    where
        F: FnOnce(&mut ratatui::Frame),
    {
        self.terminal.draw(f)?;
        Ok(())
    }

    /// Consume any pending escape sequences produced by the backend.
    pub fn drain_bytes(&self) -> Vec<u8> {
        self.terminal.backend().drain_bytes()
    }
}

/// Ratatui backend that mirrors `CrosstermBackend` but writes into a shared buffer.
#[derive(Clone)]
pub struct RemoteBackend {
    inner: CrosstermBackend<SessionWriter>,
    size: Rect,
    writer_handle: SessionWriter,
    cursor: (u16, u16),
}

impl RemoteBackend {
    /// Instantiate the backend for the provided viewport.
    pub fn new(area: Rect) -> Self {
        let writer = SessionWriter::default();
        Self {
            inner: CrosstermBackend::new(writer.clone()),
            size: area,
            writer_handle: writer,
            cursor: (0, 0),
        }
    }

    /// Update the cached area without resizing the underlying terminal yet.
    pub fn set_size(&mut self, area: Rect) {
        self.size = area;
    }

    pub fn area(&self) -> Rect {
        self.size
    }

    /// Drain the collected escape sequences so the handler can forward them over SSH.
    pub fn drain_bytes(&self) -> Vec<u8> {
        self.writer_handle.take()
    }
}

impl Backend for RemoteBackend {
    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a ratatui::buffer::Cell)>,
    {
        self.inner.draw(content)
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        self.inner.hide_cursor()
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        self.inner.show_cursor()
    }

    fn get_cursor(&mut self) -> io::Result<(u16, u16)> {
        Ok(self.cursor)
    }

    fn set_cursor(&mut self, x: u16, y: u16) -> io::Result<()> {
        self.cursor = (x, y);
        self.inner.set_cursor_position(Position { x, y })
    }

    fn clear(&mut self) -> io::Result<()> {
        self.inner.clear()
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        self.inner.clear_region(clear_type)
    }

    fn append_lines(&mut self, n: u16) -> io::Result<()> {
        self.inner.append_lines(n)
    }

    fn size(&self) -> io::Result<Size> {
        Ok(self.size.into())
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: Size {
                width: self.size.width,
                height: self.size.height,
            },
            pixels: Size { width: 0, height: 0 },
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Backend::flush(&mut self.inner)
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        self.inner.get_cursor_position()
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        self.inner.set_cursor_position(position)
    }
}

#[derive(Clone)]
struct SessionWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl Default for SessionWriter {
    fn default() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl SessionWriter {
    /// Take ownership of the buffered bytes, leaving the writer empty.
    fn take(&self) -> Vec<u8> {
        let mut guard = self.buffer.lock().unwrap();
        std::mem::take(&mut *guard)
    }
}

impl Write for SessionWriter {
    /// Append to the shared buffer; the operation is synchronized via a mutex.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.buffer.lock().unwrap();
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
