#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::{
    future::poll_fn,
    io::{Cursor, IoSlice, Read, Write},
};

use tokio::net::TcpStream;

use super::*;
use crate::common::{IoSession, SyncReadAdapter};

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) session: ServerConnection,
    pub(crate) state: TlsState,
    pub(crate) earlydata: Option<Cursor<Vec<u8>>>,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> (&IO, &ServerConnection) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut IO, &mut ServerConnection) {
        (&mut self.io, &mut self.session)
    }

    #[inline]
    pub fn into_inner(self) -> (IO, ServerConnection) {
        (self.io, self.session)
    }

    pub fn is_jls(&self) -> Option<bool> {
        self.session.is_jls()
    }
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Session = ServerConnection;

    #[inline]
    fn skip_handshake(&self) -> bool {
        false
    }

    #[inline]
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Session) {
        (&mut self.state, &mut self.io, &mut self.session)
    }

    #[inline]
    fn into_io(self) -> Self::Io {
        self.io
    }
}

impl<IO> AsyncRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut n = 0;
        if let Some(read) = &mut this.earlydata {
            n = read.read(buf.initialize_unfilled()).unwrap();
            buf.advance(n);
            if n == 0 {
                this.earlydata = None;
            } else if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            } else {
                this.earlydata = None;
            }
        }
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());

        match &this.state {
            TlsState::Stream | TlsState::WriteShutdown => {
                let prev = buf.remaining();

                match stream.as_mut_pin().poll_read(cx, buf) {
                    Poll::Ready(Ok(())) => {
                        if prev == buf.remaining() || stream.eof {
                            this.state.shutdown_read();
                        }

                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {
                        this.state.shutdown_read();
                        Poll::Ready(Err(err))
                    }
                    Poll::Pending => {
                        if n > 0 {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Pending
                        }
                    }
                    output => output,
                }
            }
            TlsState::ReadShutdown | TlsState::FullyShutdown => Poll::Ready(Ok(())),
            #[cfg(feature = "early-data")]
            s => unreachable!("server TLS can not hit this state: {:?}", s),
        }
    }
}

impl<IO> AsyncWrite for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Note: that it does not guarantee the final data to be sent.
    /// To be cautious, you must manually call `flush`.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.writeable() {
            self.session.send_close_notify();
            self.state.shutdown_write();
        }

        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
        stream.as_mut_pin().poll_shutdown(cx)
    }
}

#[cfg(unix)]
impl<IO> AsRawFd for TlsStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().0.as_raw_fd()
    }
}

#[cfg(windows)]
impl<IO> AsRawSocket for TlsStream<IO>
where
    IO: AsRawSocket,
{
    fn as_raw_socket(&self) -> RawSocket {
        self.get_ref().0.as_raw_socket()
    }
}

impl<IO> TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn forward(mut self) -> io::Result<()> {
        let mut upstream_sock;
        if let Some(addr) = self.session.get_upstream_addr() {
            upstream_sock = TcpStream::connect(addr).await.unwrap();
        } else {
            return Ok(());
        }
        let func = |cx: &mut Context<'_>| -> Poll<io::Result<()>> {
            loop {
                let cli_wants_write = self.session.wants_write();
                let mut stream =
                    Stream::new(&mut self.io, &mut self.session).set_eof(!self.state.readable());
                let mut keep_going = false;
                if cli_wants_write {
                    match stream.write_io(cx) {
                        Poll::Ready(Ok(_n)) => {
                            keep_going = true;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {}
                    }
                }
                match stream.read_io(cx) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(_n)) => {
                        keep_going = true;
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {}
                }

                let wants_write_upstream = self.session.wants_write_upstream();
                if wants_write_upstream {
                    match self.write_upstream_io(cx, &mut upstream_sock) {
                        Poll::Ready(Ok(0)) => {}
                        Poll::Ready(Ok(_n)) => {
                            keep_going = true;
                        }
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err(e).into());
                        }
                        Poll::Pending => {}
                    }
                }
                match self.read_upstream_io(cx, &mut upstream_sock) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(_n)) => {
                        keep_going = true;
                    }
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {}
                }
                if !keep_going {
                    break;
                }
            }
            Poll::Pending
        };
        poll_fn(func).await.map(|_| ())
    }

    pub fn read_upstream_io<T: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context,
        rd: &mut T,
    ) -> Poll<io::Result<usize>> {
        let mut upstream_reader = SyncReadAdapter { io: rd, cx };
        match self.session.read_upstream(&mut upstream_reader) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub fn write_upstream_io<T: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context,
        wr: &mut T,
    ) -> Poll<io::Result<usize>> {
        struct Writer<'a, 'b, T> {
            io: &'a mut T,
            cx: &'a mut Context<'b>,
        }

        impl<'a, 'b, T: Unpin> Writer<'a, 'b, T> {
            #[inline]
            fn poll_with<U>(
                &mut self,
                f: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<U>>,
            ) -> io::Result<U> {
                match f(Pin::new(self.io), self.cx) {
                    Poll::Ready(result) => result,
                    Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
                }
            }
        }

        impl<'a, 'b, T: AsyncWrite + Unpin> Write for Writer<'a, 'b, T> {
            #[inline]
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.poll_with(|io, cx| io.poll_write(cx, buf))
            }

            #[inline]
            fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
                self.poll_with(|io, cx| io.poll_write_vectored(cx, bufs))
            }

            fn flush(&mut self) -> io::Result<()> {
                self.poll_with(|io, cx| io.poll_flush(cx))
            }
        }

        let mut writer = Writer { io: wr, cx };

        match self.session.write_upstream(&mut writer) {
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }
}
