use super::*;
use crate::common::IoSession;
use std::fmt::{Debug, Formatter};
use std::mem;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use tokio::sync::oneshot::{Receiver, Sender};

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) session: ClientConnection,
    pub(crate) state: TlsState,

    #[cfg(feature = "early-data")]
    pub(crate) early_waker: Option<std::task::Waker>,
    #[cfg(feature = "early-data")]
    pub(crate) early_data_send: Option<Sender<bool>>,
    #[cfg(feature = "early-data")]
    pub(crate) early_data_accept: Option<ZeroRttAccept>,

    pub(crate) jls_handler: Box<dyn JlsHandler<IO>>,
}
impl<IO> Debug for Box<dyn JlsHandler<IO>> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "EarlyDataHandler")
    }
}
pub trait JlsHandler<IO>: Send + Sync + Unpin {
    fn handle(&mut self, stream: &mut TlsStream<IO>);
}

pub struct JlsDummyHandler;
impl<IO> JlsHandler<IO> for JlsDummyHandler {
    fn handle(&mut self, _: &mut TlsStream<IO>) {
        ()
    }
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> (&IO, &ClientConnection) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut IO, &mut ClientConnection) {
        (&mut self.io, &mut self.session)
    }

    #[inline]
    pub fn into_inner(self) -> (IO, ClientConnection) {
        (self.io, self.session)
    }

    pub fn is_jls(&self) -> Option<bool> {
        self.session.is_jls()
    }

    /// Set early data handler used for early data accepted or rejected
    pub fn set_jls_handler<T>(&mut self, handler: T)
    where
        T: JlsHandler<IO> + 'static,
    {
        self.jls_handler = Box::new(handler);
    }

    /// Check whether early data accepted
    #[cfg(feature = "early-data")]
    pub fn early_data_accepted(&mut self) -> Option<ZeroRttAccept> {
        self.early_data_accept.take()
    }
}

#[derive(Debug)]
pub struct ZeroRttAccept(pub(crate) Receiver<bool>);

impl Future for ZeroRttAccept {
    type Output = bool;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|x| x.unwrap_or(false))
    }
}

#[cfg(unix)]
impl<S> AsRawFd for TlsStream<S>
where
    S: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().0.as_raw_fd()
    }
}

#[cfg(windows)]
impl<S> AsRawSocket for TlsStream<S>
where
    S: AsRawSocket,
{
    fn as_raw_socket(&self) -> RawSocket {
        self.get_ref().0.as_raw_socket()
    }
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Session = ClientConnection;

    #[inline]
    fn skip_handshake(&self) -> bool {
        self.state.is_early_data()
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
        match self.state {
            #[cfg(feature = "early-data")]
            TlsState::EarlyData(..) => {
                let this = self.get_mut();

                // In the EarlyData state, we have not really established a Tls connection.
                // Before writing data through `AsyncWrite` and completing the tls handshake,
                // we ignore read readiness and return to pending.
                //
                // In order to avoid event loss,
                // we need to register a waker and wake it up after tls is connected.
                if this
                    .early_waker
                    .as_ref()
                    .filter(|waker| cx.waker().will_wake(waker))
                    .is_none()
                {
                    this.early_waker = Some(cx.waker().clone());
                }

                Poll::Pending
            }
            TlsState::Stream | TlsState::WriteShutdown => {
                let this = self.get_mut();
                let mut stream =
                    Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());
                let prev = buf.remaining();

                match stream.as_mut_pin().poll_read(cx, buf) {
                    Poll::Ready(Ok(())) => {
                        if prev == buf.remaining() || stream.eof {
                            this.state.shutdown_read();
                        }

                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::ConnectionAborted => {
                        this.state.shutdown_read();
                        Poll::Ready(Err(err))
                    }
                    output => output,
                }
            }
            TlsState::ReadShutdown | TlsState::FullyShutdown => Poll::Ready(Ok(())),
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

        #[allow(clippy::match_single_binding)]
        let output = match this.state {
            #[cfg(feature = "early-data")]
            TlsState::EarlyData(ref mut pos, ref mut data) => {
                use std::io::Write;

                // write early data
                if let Some(mut early_data) = stream.session.early_data() {
                    let len = match early_data.write(buf) {
                        Ok(n) => n,
                        Err(err) => return Poll::Ready(Err(err)),
                    };
                    if len != 0 {
                        data.extend_from_slice(&buf[..len]);
                        return Poll::Ready(Ok(len));
                    }
                }

                // complete handshake
                while stream.session.is_handshaking() {
                    ready!(stream.handshake(cx))?;
                }

                // write early data (fallback)
                if !stream.session.is_early_data_accepted() {
                    this.early_data_send.take().unwrap().send(false).unwrap();
                    while *pos < data.len() {
                        let len = ready!(stream.as_mut_pin().poll_write(cx, &data[*pos..]))?;
                        *pos += len;
                    }
                } else {
                    this.early_data_send.take().unwrap().send(true).unwrap();
                }

                // end
                this.state = TlsState::Stream;

                if let Some(waker) = this.early_waker.take() {
                    waker.wake();
                }

                stream.as_mut_pin().poll_write(cx, buf)
            }
            _ => stream.as_mut_pin().poll_write(cx, buf),
        };
        let mut handler = mem::replace(
            &mut this.jls_handler,
            Box::new(JlsDummyHandler {}),
        );
        handler.handle(this);

        output
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.session).set_eof(!this.state.readable());

        #[cfg(feature = "early-data")]
        {
            if let TlsState::EarlyData(ref mut pos, ref mut data) = this.state {
                // complete handshake
                while stream.session.is_handshaking() {
                    ready!(stream.handshake(cx))?;
                }

                // write early data (fallback)
                if !stream.session.is_early_data_accepted() {
                    this.early_data_send.take().unwrap().send(false).unwrap();
                    while *pos < data.len() {
                        let len = ready!(stream.as_mut_pin().poll_write(cx, &data[*pos..]))?;
                        *pos += len;
                    }
                } else {
                    this.early_data_send.take().unwrap().send(true).unwrap();
                }

                this.state = TlsState::Stream;

                if let Some(waker) = this.early_waker.take() {
                    waker.wake();
                }
            }
        }

        let output = stream.as_mut_pin().poll_flush(cx);

        let mut handler = mem::replace(
                &mut this.jls_handler,
                Box::new(JlsDummyHandler {}),
            );
        handler.handle(this);

        output
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        #[cfg(feature = "early-data")]
        {
            // complete handshake
            if matches!(self.state, TlsState::EarlyData(..)) {
                ready!(self.as_mut().poll_flush(cx))?;
            }
        }

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
