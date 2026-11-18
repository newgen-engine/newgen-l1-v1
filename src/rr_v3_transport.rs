//! Shared RRv3 transport primitives.
//!
//! RRv3 is used for: header sync (Step 57) and snapshot-v2 serving (Phase 5).
//! We keep the codec shared so bins (e.g. fetch_snapshot_v2) and the runtime P2P
//! node stay wire-compatible.

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response;
use std::future::Future;
use std::io;
use std::pin::Pin;

/// RRv3 request payload.
#[derive(Clone, Debug)]
pub struct RRv3Request(pub Vec<u8>);

/// RRv3 response payload.
#[derive(Clone, Debug)]
pub struct RRv3Response(pub Vec<u8>);

/// Length-prefixed (u32 BE) codec used by NewGen RRv3.
///
/// Frame caps are enforced *before* allocation to avoid memory abuse.
#[derive(Clone)]
pub struct NewgenHeadersCodec {
    pub max_frame_bytes: usize,
}

impl request_response::Codec for NewgenHeadersCodec {
    type Protocol = String;
    type Request = RRv3Request;
    type Response = RRv3Response;

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Request>> + Send + 'async_trait>>
    where
        T: AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let cap = self.max_frame_bytes;
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            io.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > cap {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("RRv3 request frame too large: {len}"),
                ));
            }
            let mut buf = vec![0u8; len];
            io.read_exact(&mut buf).await?;
            Ok(RRv3Request(buf))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send + 'async_trait>>
    where
        T: AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let cap = self.max_frame_bytes;
        Box::pin(async move {
            let mut len_buf = [0u8; 4];
            io.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > cap {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("RRv3 response frame too large: {len}"),
                ));
            }
            let mut buf = vec![0u8; len];
            io.read_exact(&mut buf).await?;
            Ok(RRv3Response(buf))
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        data: Self::Request,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        T: AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let cap = self.max_frame_bytes;
        Box::pin(async move {
            let data = data.0;
            let len = data.len();
            if len > cap {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "RRv3 request too large",
                ));
            }
            io.write_all(&(len as u32).to_be_bytes()).await?;
            io.write_all(&data).await?;
            io.flush().await?;
            Ok(())
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        data: Self::Response,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'async_trait>>
    where
        T: AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let cap = self.max_frame_bytes;
        Box::pin(async move {
            let data = data.0;
            let len = data.len();
            if len > cap {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "RRv3 response too large",
                ));
            }
            io.write_all(&(len as u32).to_be_bytes()).await?;
            io.write_all(&data).await?;
            io.flush().await?;
            Ok(())
        })
    }
}
