use std::path::PathBuf;

use async_trait::async_trait;
use russh::{Channel, ChannelStream, client};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::session::{SessionHandle, SharedSessionHandle};

// Internal Result type alias for convenience
type Result<T> = crate::SshResult<T>;

/// Trait for streams that can be used for forwarding.
pub trait ForwardStreamIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ForwardStreamIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Type alias for boxed forward streams.
pub type ForwardStream = Box<dyn ForwardStreamIo>;

/// Trait for sessions that can open forwarding connections.
#[async_trait]
pub trait ForwardSession: Clone + Send + Sync + 'static {
    async fn open_direct_tcpip(
        &self,
        target_host: String,
        target_port: u16,
        origin_host: String,
        origin_port: u16,
    ) -> Result<ForwardStream>;

    #[cfg(unix)]
    async fn open_direct_streamlocal(&self, remote_socket: PathBuf) -> Result<ForwardStream>;

    async fn cancel_tcpip_forwarding(&self, bind_address: String, port: u32) -> Result<()>;

    #[cfg(unix)]
    async fn cancel_streamlocal_forwarding(&self, remote_socket: String) -> Result<()>;
}

/// Trait for channels that can handle remote forwarding.
#[async_trait]
pub trait RemoteForwardChannel: Send {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn into_stream(self) -> Self::Stream;
    async fn close(self) -> Result<()>;
}

/// Trait for registering remote forwards with the server.
#[async_trait]
pub trait RemoteRegistrar {
    async fn request_tcpip_forward(&mut self, bind_address: String, bind_port: u16) -> Result<u32>;

    #[cfg(unix)]
    async fn request_streamlocal_forward(&mut self, remote_socket: String) -> Result<()>;
}

// Trait implementations for russh types

#[async_trait]
impl<H> ForwardSession for SharedSessionHandle<H>
where
    H: client::Handler + Send + Sync + 'static,
{
    async fn open_direct_tcpip(
        &self,
        target_host: String,
        target_port: u16,
        origin_host: String,
        origin_port: u16,
    ) -> Result<ForwardStream> {
        let channel = self
            .as_ref()
            .channel_open_direct_tcpip(target_host, target_port.into(), origin_host, origin_port.into())
            .await?;
        Ok(Box::new(channel.into_stream()))
    }

    #[cfg(unix)]
    async fn open_direct_streamlocal(&self, remote_socket: PathBuf) -> Result<ForwardStream> {
        let remote_path = remote_socket.to_string_lossy().to_string();
        let channel = self.as_ref().channel_open_direct_streamlocal(remote_path).await?;
        Ok(Box::new(channel.into_stream()))
    }

    async fn cancel_tcpip_forwarding(&self, bind_address: String, port: u32) -> Result<()> {
        self.as_ref().cancel_tcpip_forward(bind_address, port).await?;
        Ok(())
    }

    #[cfg(unix)]
    async fn cancel_streamlocal_forwarding(&self, remote_socket: String) -> Result<()> {
        self.as_ref().cancel_streamlocal_forward(remote_socket).await?;
        Ok(())
    }
}

#[async_trait]
impl<H> RemoteRegistrar for SessionHandle<H>
where
    H: client::Handler + Send,
{
    async fn request_tcpip_forward(&mut self, bind_address: String, bind_port: u16) -> Result<u32> {
        let assigned = self.tcpip_forward(bind_address, bind_port.into()).await?;
        Ok(assigned)
    }

    #[cfg(unix)]
    async fn request_streamlocal_forward(&mut self, remote_socket: String) -> Result<()> {
        self.streamlocal_forward(remote_socket).await?;
        Ok(())
    }
}

#[async_trait]
impl RemoteForwardChannel for Channel<client::Msg> {
    type Stream = ChannelStream<client::Msg>;

    fn into_stream(self) -> Self::Stream {
        Channel::into_stream(self)
    }

    async fn close(self) -> Result<()> {
        Channel::close(&self).await?;
        Ok(())
    }
}
