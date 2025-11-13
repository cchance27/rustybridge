//! Ratatui backend plumbing that knows how to emit escape sequences over russh channels.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use ratatui::backend::{Backend, ClearType, CrosstermBackend, WindowSize};
use ratatui::layout::{Position, Rect, Size};
use ratatui::{Frame, Terminal};

/// Owns a [`Terminal`] configured with the custom backend that writes into an in-memory buffer.
///
/// The handler renders into this terminal and later drains the bytes to forward over SSH.
pub(super) struct ServerTerminal {
    terminal: Terminal<RemoteBackend>,
}

impl ServerTerminal {
    /// Create a new terminal tied to a fixed area. The backend can be resized later.
    pub(super) fn new(area: Rect) -> io::Result<Self> {
        let backend = RemoteBackend::new(area);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    /// Ensure the terminal's viewport matches the remote PTY dimensions.
    pub(super) fn ensure_size(&mut self, area: Rect) -> io::Result<()> {
        if self.terminal.backend().area() != area {
            self.terminal.backend_mut().set_size(area);
            self.terminal.resize(area)?;
        }
        Ok(())
    }

    /// Render a frame using ratatui's differential draw API.
    pub(super) fn draw<F>(&mut self, f: F) -> io::Result<()>
    where
        F: FnOnce(&mut Frame),
    {
        self.terminal.draw(f)?;
        Ok(())
    }

    /// Consume any pending escape sequences produced by the backend.
    pub(super) fn drain_bytes(&self) -> Vec<u8> {
        self.terminal.backend().drain_bytes()
    }
}

/// Ratatui backend that mirrors `CrosstermBackend` but writes into a shared buffer.
#[derive(Clone)]
pub(super) struct RemoteBackend {
    inner: CrosstermBackend<SessionWriter>,
    size: Rect,
    writer_handle: SessionWriter,
}

impl RemoteBackend {
    /// Instantiate the backend for the provided viewport.
    pub(super) fn new(area: Rect) -> Self {
        let writer = SessionWriter::default();
        Self {
            inner: CrosstermBackend::new(writer.clone()),
            size: area,
            writer_handle: writer,
        }
    }

    /// Update the cached area without resizing the underlying terminal yet.
    pub(super) fn set_size(&mut self, area: Rect) {
        self.size = area;
    }

    pub(super) fn area(&self) -> Rect {
        self.size
    }

    /// Drain the collected escape sequences so the handler can forward them over SSH.
    pub(super) fn drain_bytes(&self) -> Vec<u8> {
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
        let position = self.inner.get_cursor_position()?;
        Ok((position.x, position.y))
    }

    fn set_cursor(&mut self, x: u16, y: u16) -> io::Result<()> {
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
            pixels: Size {
                width: 0,
                height: 0,
            },
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
