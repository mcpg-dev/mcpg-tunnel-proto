//! The tunnel session layer: yamux multiplexing over any single byte
//! transport (a TLS WebSocket in production, an in-memory duplex in tests),
//! with each MCP request carried on its own mux stream.
//!
//! Roles are asymmetric and fixed:
//! - the **agent** ([`AgentSession`]) dials out, opens the one **control
//!   stream**, and completes the handshake, then *accepts* the request
//!   streams the relay opens;
//! - the **relay** ([`RelaySession`]) accepts the connection + control
//!   stream, validates the handshake, then *opens* one request stream per
//!   inbound public request.
//!
//! yamux speaks futures-io while `tokio_util::codec` speaks tokio-io, so the
//! outer transport and every accepted stream are bridged with the compat
//! shims. yamux's `Connection` is poll-driven and not shareable across
//! tasks, so a per-session driver task owns it and services outbound opens
//! (over a channel) and inbound accepts (into a channel).

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tokio_util::codec::Framed;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::codec::FrameCodec;
use crate::error::ProtoError;
use crate::frame::{Frame, TunnelError};
use crate::handshake::{HandshakeRequest, HandshakeResponse};

/// A framed, full-duplex tunnel stream carrying [`Frame`]s. One of these is
/// the control stream; each of the others carries a single MCP
/// request/response exchange.
pub struct FrameStream {
    inner: Framed<Compat<yamux::Stream>, FrameCodec>,
    /// A relay request stream's place in [`RELAY_MAX_REQUESTS`], given back
    /// when the stream is dropped.
    _slot: Option<OwnedSemaphorePermit>,
}

impl FrameStream {
    fn new(stream: yamux::Stream) -> Self {
        Self {
            inner: Framed::new(stream.compat(), FrameCodec),
            _slot: None,
        }
    }

    /// Send one frame.
    pub async fn send(&mut self, frame: Frame) -> Result<(), ProtoError> {
        self.inner.send(frame).await
    }

    /// Receive the next frame, or `None` at end of stream.
    pub async fn recv(&mut self) -> Result<Option<Frame>, ProtoError> {
        self.inner.next().await.transpose()
    }

    /// Flush and half-close the write side, signalling the end of this
    /// exchange to the peer.
    pub async fn close(&mut self) -> Result<(), ProtoError> {
        self.inner.close().await
    }
}

type OpenReply = oneshot::Sender<Result<yamux::Stream, ProtoError>>;

/// The driver's ends of the [`Mux`] channels. The closed sender is held for
/// the driver's lifetime and dropped when it returns, which resolves the
/// `RelaySession::closed` watch receivers.
type DriverChannels = (
    mpsc::UnboundedReceiver<OpenReply>,
    mpsc::UnboundedSender<yamux::Stream>,
    oneshot::Receiver<()>,
    watch::Sender<()>,
);

/// How a session notices a peer that vanished without closing the connection
/// — a host that lost power, a NAT or load balancer that dropped the flow.
/// Nothing arrives to say so, and the socket stays open indefinitely.
///
/// yamux sends a ping to measure round-trip time every ten seconds while its
/// connection is driven, and every yamux peer answers one, so a live peer is
/// never silent for long. The driver wakes every `ping_every` so an idle
/// connection is driven too, and ends the session once nothing has arrived
/// from the peer for `dead_after`. `dead_after` must comfortably exceed ten
/// seconds plus `ping_every`, or an idle but live peer is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionKeepalive {
    pub ping_every: Duration,
    pub dead_after: Duration,
}

/// When the transport under a session last delivered bytes from the peer.
#[derive(Clone)]
struct LastRead {
    origin: Instant,
    /// Milliseconds after `origin`.
    at: Arc<AtomicU64>,
}

impl LastRead {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            at: Arc::default(),
        }
    }

    fn mark(&self) {
        let now = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.at.store(now, Ordering::Relaxed);
    }

    fn silent_for(&self) -> Duration {
        let at = Duration::from_millis(self.at.load(Ordering::Relaxed));
        self.origin.elapsed().saturating_sub(at)
    }
}

/// A transport that records every read that delivered bytes.
struct Watched<T> {
    io: T,
    last_read: LastRead,
}

impl<T: AsyncRead + Unpin> AsyncRead for Watched<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.io).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.last_read.mark();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Watched<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// The driver's half of [`SessionKeepalive`]: the wake-up timer and the
/// transport's last read.
struct Watchdog {
    wake: Interval,
    last_read: LastRead,
    dead_after: Duration,
}

impl Watchdog {
    fn new(keepalive: SessionKeepalive, last_read: LastRead) -> Self {
        let mut wake = tokio::time::interval(keepalive.ping_every);
        wake.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Self {
            wake,
            last_read,
            dead_after: keepalive.dead_after,
        }
    }

    /// Whether the peer has gone silent for too long. Polling the timer also
    /// schedules the next wake-up on `cx`.
    fn peer_is_dead(&mut self, cx: &mut Context<'_>) -> bool {
        while self.wake.poll_tick(cx).is_ready() {
            if self.last_read.silent_for() >= self.dead_after {
                return true;
            }
        }
        false
    }
}

/// Handle to the per-session yamux driver: request outbound streams, receive
/// inbound ones.
struct Mux {
    open_tx: mpsc::UnboundedSender<OpenReply>,
    inbound_rx: mpsc::UnboundedReceiver<yamux::Stream>,
    // Dropping this signals the driver to flush pending writes and close the
    // connection *gracefully*. Aborting the driver instead would race the
    // flush — a final in-band frame (e.g. a handshake rejection) could be
    // lost before it reaches the peer. The driver self-terminates once the
    // close completes, so no task leaks.
    _shutdown: oneshot::Sender<()>,
    // Resolves once the driver task exits (connection closed). Cloned out via
    // `RelaySession::closed` so the relay learns a tunnel died without polling.
    closed_rx: watch::Receiver<()>,
}

impl Mux {
    fn spawn<T>(io: T, mode: yamux::Mode, keepalive: Option<SessionKeepalive>) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (open_tx, open_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (closed_tx, closed_rx) = watch::channel(());
        let channels = (open_rx, inbound_tx, shutdown_rx, closed_tx);
        match keepalive {
            None => {
                let conn = yamux::Connection::new(io.compat(), mux_config(), mode);
                tokio::spawn(drive(conn, channels, None));
            }
            Some(keepalive) => {
                let last_read = LastRead::new();
                let io = Watched {
                    io,
                    last_read: last_read.clone(),
                };
                let conn = yamux::Connection::new(io.compat(), mux_config(), mode);
                let watchdog = Watchdog::new(keepalive, last_read);
                tokio::spawn(drive(conn, channels, Some(watchdog)));
            }
        }
        Self {
            open_tx,
            inbound_rx,
            _shutdown: shutdown_tx,
            closed_rx,
        }
    }

    async fn open(&self) -> Result<FrameStream, ProtoError> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .map_err(|_| ProtoError::SessionClosed)?;
        let stream = rx.await.map_err(|_| ProtoError::SessionClosed)??;
        Ok(FrameStream::new(stream))
    }

    /// Take the next inbound stream and acknowledge it at once. yamux
    /// otherwise acknowledges a stream only with the first frame sent on it,
    /// and the opener stops opening while 256 streams wait for that: a
    /// gateway slow to answer would hold the relay below its own limit.
    async fn accept(&mut self) -> Option<FrameStream> {
        let mut stream = self.inbound_rx.recv().await?;
        // An empty write sends a header-only frame that carries the
        // acknowledgement. It fails only on a stream the peer has already
        // reset, which the reader then sees end.
        let _ = futures::AsyncWriteExt::write(&mut stream, &[]).await;
        Some(FrameStream::new(stream))
    }
}

/// Request streams a relay session holds open at once. One more request is
/// refused with [`ProtoError::Busy`] and never reaches the mux.
pub const RELAY_MAX_REQUESTS: usize = 512;

/// The mux's own stream limit, on both ends. Either end that reaches it ends
/// the whole connection: the opener on an open past it, the receiver on a
/// stream opened past it. Each end still counts a stream after the relay has
/// dropped it (the relay until its mux processes the drop, the agent until
/// it notices), so the limit sits far above [`RELAY_MAX_REQUESTS`].
const MUX_MAX_STREAMS: usize = 4 * RELAY_MAX_REQUESTS;

fn mux_config() -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(MUX_MAX_STREAMS);
    config
}

fn conn_err(e: yamux::ConnectionError) -> ProtoError {
    ProtoError::Io(std::io::Error::other(e.to_string()))
}

/// Owns the yamux `Connection` and drives it to completion. `poll_next_inbound`
/// must be polled to make *any* progress (it also flushes queued outbound
/// frames), so the loop always drives it; pending outbound-open requests are
/// serviced opportunistically as `poll_new_outbound` becomes ready.
async fn drive<T>(
    mut conn: yamux::Connection<Compat<T>>,
    (mut open_rx, inbound_tx, mut shutdown_rx, _closed_tx): DriverChannels,
    mut watchdog: Option<Watchdog>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut pending: VecDeque<OpenReply> = VecDeque::new();
    let mut open_closed = false;
    let mut shutting_down = false;

    loop {
        let keep_going = std::future::poll_fn(|cx| {
            // A silent peer ends the session without a graceful close: the
            // close would wait on writes the peer never acknowledges.
            if let Some(watchdog) = watchdog.as_mut()
                && watchdog.peer_is_dead(cx)
            {
                return Poll::Ready(false);
            }
            // A dropped session (shutdown sender gone) or an explicit signal
            // flips us into graceful close: flush queued frames, then stop.
            if !shutting_down && Pin::new(&mut shutdown_rx).poll(cx).is_ready() {
                shutting_down = true;
            }
            if shutting_down {
                for tx in pending.drain(..) {
                    let _ = tx.send(Err(ProtoError::SessionClosed));
                }
                return match conn.poll_close(cx) {
                    Poll::Ready(_) => Poll::Ready(false),
                    Poll::Pending => Poll::Pending,
                };
            }

            // Drain newly-requested opens into the pending queue.
            while !open_closed {
                match open_rx.poll_recv(cx) {
                    Poll::Ready(Some(tx)) => pending.push_back(tx),
                    Poll::Ready(None) => open_closed = true,
                    Poll::Pending => break,
                }
            }

            // Try to satisfy one pending open.
            if !pending.is_empty() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        let _ = pending.pop_front().unwrap().send(Ok(stream));
                        return Poll::Ready(true);
                    }
                    Poll::Ready(Err(e)) => {
                        let _ = pending.pop_front().unwrap().send(Err(conn_err(e)));
                        return Poll::Ready(true);
                    }
                    Poll::Pending => {}
                }
            }

            // Drive the connection; yields inbound streams and flushes outbound.
            match conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    let _ = inbound_tx.send(stream);
                    Poll::Ready(true)
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => Poll::Ready(false),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;

        if !keep_going {
            break;
        }
    }
}

/// The agent (gateway / thin-client) end of a tunnel.
pub struct AgentSession {
    mux: Mux,
    // The control stream is kept alive for the session's lifetime (it carries
    // the handshake and future control/heartbeat frames); dropping the
    // session half-closes it.
    _control: FrameStream,
}

impl AgentSession {
    /// Dial a relay over `io`, open the control stream, and complete the
    /// handshake. Validates the spec locally first so a malformed request
    /// never leaves the machine.
    pub async fn connect<T>(
        io: T,
        req: HandshakeRequest,
    ) -> Result<(Self, HandshakeResponse), ProtoError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        req.spec.validate()?;
        let mux = Mux::spawn(io, yamux::Mode::Client, None);
        let mut control = mux.open().await?;
        control.send(Frame::HandshakeRequest(req)).await?;
        let resp = match control.recv().await? {
            Some(Frame::HandshakeResponse(r)) => r,
            Some(Frame::Error(e)) => {
                return Err(ProtoError::Rejected(format!("{}: {}", e.code, e.message)));
            }
            _ => return Err(ProtoError::SessionClosed),
        };
        Ok((
            Self {
                mux,
                _control: control,
            },
            resp,
        ))
    }

    /// Accept the next request stream the relay opens (one per inbound MCP
    /// request). `None` once the session closes.
    pub async fn accept(&mut self) -> Option<FrameStream> {
        self.mux.accept().await
    }
}

/// The relay end of a tunnel.
pub struct RelaySession {
    mux: Mux,
    _control: FrameStream,
    /// Places for [`RELAY_MAX_REQUESTS`] open request streams.
    requests: Arc<Semaphore>,
}

impl RelaySession {
    /// Accept a dialing agent over `io`, receive its handshake, and reply with
    /// the result of `on_handshake` — where the relay applies its own policy
    /// (spec validity, auth, quota, entitlement, suspension). On rejection an
    /// in-band error frame is sent and the error is returned.
    pub async fn accept<T, F>(
        io: T,
        on_handshake: F,
    ) -> Result<(Self, HandshakeRequest), ProtoError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: AsyncFnOnce(&HandshakeRequest) -> Result<HandshakeResponse, ProtoError>,
    {
        Self::accept_inner(io, None, on_handshake).await
    }

    /// [`Self::accept`], closing the session once the agent goes silent for
    /// `keepalive.dead_after` — during the handshake too, so a dialer that
    /// never speaks does not hold the accept task.
    pub async fn accept_with_keepalive<T, F>(
        io: T,
        keepalive: SessionKeepalive,
        on_handshake: F,
    ) -> Result<(Self, HandshakeRequest), ProtoError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: AsyncFnOnce(&HandshakeRequest) -> Result<HandshakeResponse, ProtoError>,
    {
        Self::accept_inner(io, Some(keepalive), on_handshake).await
    }

    async fn accept_inner<T, F>(
        io: T,
        keepalive: Option<SessionKeepalive>,
        on_handshake: F,
    ) -> Result<(Self, HandshakeRequest), ProtoError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        // Async so the relay's policy can make an authoritative control-plane
        // call (org resolution, quota, suspension, entitlement) and reject
        // in-band before the handshake response is sent.
        F: AsyncFnOnce(&HandshakeRequest) -> Result<HandshakeResponse, ProtoError>,
    {
        let mut mux = Mux::spawn(io, yamux::Mode::Server, keepalive);
        let mut control = mux.accept().await.ok_or(ProtoError::SessionClosed)?;
        let req = match control.recv().await? {
            Some(Frame::HandshakeRequest(r)) => r,
            _ => return Err(ProtoError::SessionClosed),
        };
        match on_handshake(&req).await {
            Ok(resp) => control.send(Frame::HandshakeResponse(resp)).await?,
            Err(e) => {
                let _ = control
                    .send(Frame::Error(TunnelError::new(
                        "handshake_rejected",
                        e.to_string(),
                    )))
                    .await;
                return Err(e);
            }
        }
        Ok((
            Self {
                mux,
                _control: control,
                requests: Arc::new(Semaphore::new(RELAY_MAX_REQUESTS)),
            },
            req,
        ))
    }

    /// Open a request stream to the agent (one per inbound public request),
    /// or refuse it with [`ProtoError::Busy`] while [`RELAY_MAX_REQUESTS`]
    /// streams are open. The stream's place is freed when it is dropped.
    pub async fn open_request(&self) -> Result<FrameStream, ProtoError> {
        let slot = self
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| ProtoError::Busy)?;
        let mut stream = self.mux.open().await?;
        stream._slot = Some(slot);
        Ok(stream)
    }

    /// A watch handle that resolves once the tunnel connection closes (peer
    /// hang-up or transport error). The relay's per-tunnel lifecycle task
    /// awaits `changed()` on it to flush final metering and deregister the
    /// tunnel promptly, rather than waiting for lazy eviction on the next
    /// request. Cheap to clone; awaiting a clone never blocks the data path.
    pub fn closed(&self) -> watch::Receiver<()> {
        self.mux.closed_rx.clone()
    }

    /// Whether the tunnel connection has already closed.
    pub fn is_closed(&self) -> bool {
        self.mux.closed_rx.has_changed().is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{Exposure, TrustMode, TunnelSpec};
    use crate::http::{AttestedMeta, RequestHead, ResponseHead};
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr};

    fn private_spec() -> TunnelSpec {
        TunnelSpec {
            name: Some("acme-crm".to_owned()),
            exposure: Exposure::Private,
            mode: TrustMode::RelayTerminated,
        }
    }

    async fn ok_handshake(req: &HandshakeRequest) -> Result<HandshakeResponse, ProtoError> {
        req.spec.validate()?;
        Ok(HandshakeResponse {
            accepted_proto_version: req.proto_version.clone(),
            tunnel_id: "acme-crm-7f3a".to_owned(),
            // A private tunnel exposes no public URL.
            public_url: match req.spec.exposure {
                Exposure::Public => Some("https://acme-crm-7f3a.tunnels.mcpg.cloud/mcp".to_owned()),
                Exposure::Private => None,
            },
            heartbeat_secs: 30,
        })
    }

    /// Drain a request stream on the agent side (RequestHead + body to
    /// BodyEnd), then answer with a 200 + a body + BodyEnd.
    async fn agent_echo_once(agent: &mut AgentSession) {
        let mut s = agent.accept().await.expect("a request stream");
        let head = s.recv().await.unwrap().unwrap();
        assert!(matches!(head, Frame::RequestHead(_)));
        // Consume request body.
        loop {
            match s.recv().await.unwrap() {
                Some(Frame::BodyChunk(_)) => {}
                Some(Frame::BodyEnd) => break,
                other => panic!("unexpected request body frame: {other:?}"),
            }
        }
        s.send(Frame::ResponseHead(ResponseHead {
            status: 200,
            headers: vec![],
        }))
        .await
        .unwrap();
        s.send(Frame::BodyChunk(Bytes::from_static(b"pong")))
            .await
            .unwrap();
        s.send(Frame::BodyEnd).await.unwrap();
        s.close().await.unwrap();
    }

    #[tokio::test]
    async fn closed_resolves_only_after_the_agent_disconnects() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let relay_task =
            tokio::spawn(async move { RelaySession::accept(server_io, ok_handshake).await });
        let (agent, _resp) =
            AgentSession::connect(client_io, HandshakeRequest::new("inst-1", private_spec()))
                .await
                .unwrap();
        let (relay, _req) = relay_task.await.unwrap().unwrap();

        let mut closed = relay.closed();
        // Still connected: the signal must not resolve.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), closed.changed())
                .await
                .is_err(),
            "closed() resolved while the tunnel was still up"
        );
        assert!(!relay.is_closed());

        // Dropping the agent tears its transport down; the relay driver ends and
        // its closed sender drops, so `changed()` resolves (Err = sender gone).
        drop(agent);
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(2), closed.changed())
            .await
            .is_ok();
        assert!(
            resolved,
            "closed() must resolve after the agent disconnects"
        );
        assert!(relay.is_closed());
    }

    /// An agent transport that can be cut off without being closed, the way a
    /// host that lost power looks from the other end: reads never complete
    /// and writes vanish.
    struct Severable<T> {
        io: T,
        cut: Arc<std::sync::atomic::AtomicBool>,
    }

    impl<T> Severable<T> {
        fn is_cut(&self) -> bool {
            self.cut.load(Ordering::SeqCst)
        }
    }

    impl<T: AsyncRead + Unpin> AsyncRead for Severable<T> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.is_cut() {
                return Poll::Pending;
            }
            Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for Severable<T> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.is_cut() {
                return Poll::Ready(Ok(buf.len()));
            }
            Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.is_cut() {
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut self.get_mut().io).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.is_cut() {
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
        }
    }

    /// One request/response exchange from the relay side.
    async fn round_trip(relay: &RelaySession) -> Result<(), ProtoError> {
        let mut s = relay.open_request().await?;
        s.send(Frame::RequestHead(RequestHead {
            method: "POST".to_owned(),
            path: "/mcp".to_owned(),
            query: None,
            headers: vec![],
            attested: AttestedMeta::default(),
        }))
        .await?;
        s.send(Frame::BodyEnd).await?;
        match s.recv().await? {
            Some(Frame::ResponseHead(h)) if h.status == 200 => Ok(()),
            other => Err(ProtoError::Protocol(format!("unexpected frame {other:?}"))),
        }
    }

    /// Bring up a relay session with `keepalive` against an agent that answers
    /// every request, over a transport the returned flag can cut.
    async fn watched_session(
        keepalive: SessionKeepalive,
    ) -> (RelaySession, Arc<std::sync::atomic::AtomicBool>) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let cut = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let relay_task = tokio::spawn(async move {
            RelaySession::accept_with_keepalive(server_io, keepalive, ok_handshake).await
        });
        let io = Severable {
            io: client_io,
            cut: cut.clone(),
        };
        let (mut agent, _resp) =
            AgentSession::connect(io, HandshakeRequest::new("inst-1", private_spec()))
                .await
                .unwrap();
        tokio::spawn(async move {
            loop {
                agent_echo_once(&mut agent).await;
            }
        });
        let (relay, _req) = relay_task.await.unwrap().unwrap();
        (relay, cut)
    }

    /// Traffic from the agent keeps its session open; once the agent goes
    /// silent without closing anything, the relay closes the session itself.
    #[tokio::test]
    async fn a_session_whose_agent_goes_silent_is_closed() {
        let keepalive = SessionKeepalive {
            ping_every: Duration::from_millis(20),
            dead_after: Duration::from_millis(400),
        };
        let (relay, cut) = watched_session(keepalive).await;
        let mut closed = relay.closed();

        for _ in 0..10 {
            round_trip(&relay).await.expect("a live agent answers");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!relay.is_closed(), "an agent that answers stays connected");

        cut.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), closed.changed())
            .await
            .expect("the relay closes a session whose agent went silent")
            .unwrap_err();
        assert!(relay.is_closed());
        assert!(round_trip(&relay).await.is_err());
    }

    /// An idle agent sends nothing of its own. The mux's round-trip pings are
    /// what keep it from looking dead, and they come every ten seconds, so
    /// this test has to outlast one of them.
    #[tokio::test]
    async fn an_idle_agent_that_answers_pings_stays_connected() {
        let keepalive = SessionKeepalive {
            ping_every: Duration::from_millis(250),
            dead_after: Duration::from_secs(14),
        };
        let (relay, _cut) = watched_session(keepalive).await;
        tokio::time::sleep(Duration::from_secs(17)).await;
        assert!(
            !relay.is_closed(),
            "an idle agent that answers pings must not be taken for dead"
        );
        round_trip(&relay).await.expect("the session still serves");
    }

    #[tokio::test]
    async fn handshake_then_request_response_roundtrip() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let relay = tokio::spawn(async move {
            let (relay, req) = RelaySession::accept(server_io, ok_handshake).await.unwrap();
            assert_eq!(req.instance_uid, "inst-1");
            assert_eq!(req.spec.exposure, Exposure::Private);

            let mut s = relay.open_request().await.unwrap();
            s.send(Frame::RequestHead(RequestHead {
                method: "POST".to_owned(),
                path: "/mcp".to_owned(),
                query: None,
                headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                attested: AttestedMeta {
                    client_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
                    tls: None,
                },
            }))
            .await
            .unwrap();
            s.send(Frame::BodyChunk(Bytes::from_static(b"ping")))
                .await
                .unwrap();
            s.send(Frame::BodyEnd).await.unwrap();

            // Response head + body.
            let head = s.recv().await.unwrap().unwrap();
            assert!(matches!(head, Frame::ResponseHead(h) if h.status == 200));
            let mut body = Vec::new();
            loop {
                match s.recv().await.unwrap() {
                    Some(Frame::BodyChunk(b)) => body.extend_from_slice(&b),
                    Some(Frame::BodyEnd) => break,
                    None => break,
                    other => panic!("unexpected response frame: {other:?}"),
                }
            }
            assert_eq!(&body, b"pong");
        });

        let (mut agent, resp) =
            AgentSession::connect(client_io, HandshakeRequest::new("inst-1", private_spec()))
                .await
                .unwrap();
        // Private tunnel → no public URL surfaced.
        assert_eq!(resp.tunnel_id, "acme-crm-7f3a");
        assert_eq!(resp.public_url, None);

        agent_echo_once(&mut agent).await;
        relay.await.unwrap();
    }

    #[tokio::test]
    async fn multiple_concurrent_request_streams() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let relay = tokio::spawn(async move {
            let (relay, _req) = RelaySession::accept(server_io, ok_handshake).await.unwrap();
            // Open three request streams and confirm each gets its own 200.
            let mut streams = Vec::new();
            for _ in 0..3 {
                let mut s = relay.open_request().await.unwrap();
                s.send(Frame::RequestHead(RequestHead {
                    method: "POST".to_owned(),
                    path: "/mcp".to_owned(),
                    query: None,
                    headers: vec![],
                    attested: AttestedMeta::default(),
                }))
                .await
                .unwrap();
                s.send(Frame::BodyEnd).await.unwrap();
                streams.push(s);
            }
            for mut s in streams {
                let head = s.recv().await.unwrap().unwrap();
                assert!(matches!(head, Frame::ResponseHead(h) if h.status == 200));
            }
        });

        let (mut agent, _resp) =
            AgentSession::connect(client_io, HandshakeRequest::new("inst-1", private_spec()))
                .await
                .unwrap();
        for _ in 0..3 {
            agent_echo_once(&mut agent).await;
        }
        relay.await.unwrap();
    }

    /// The relay drops a request stream as soon as its client goes away,
    /// while the agent keeps its end until it notices. Streams the agent
    /// still holds never end the session: the relay's own stream limit
    /// refuses an open first, and the session goes on serving.
    #[tokio::test]
    async fn streams_the_agent_still_holds_never_close_the_session() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (agent_res, relay_res) = tokio::join!(
            AgentSession::connect(client_io, HandshakeRequest::new("inst-1", private_spec())),
            RelaySession::accept(server_io, ok_handshake),
        );
        let (mut agent, _resp) = agent_res.unwrap();
        let (relay, _req) = relay_res.unwrap();
        // `/slow` is held unanswered, `/hold` is answered with a head and
        // held, `/ping` is answered.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(mut s) = agent.accept().await {
                let path = match s.recv().await {
                    Ok(Some(Frame::RequestHead(h))) => h.path,
                    _ => continue,
                };
                if path != "/slow" {
                    let head = Frame::ResponseHead(ResponseHead {
                        status: 200,
                        headers: vec![],
                    });
                    if s.send(head).await.is_err() {
                        continue;
                    }
                }
                if path != "/ping" {
                    held.push(s);
                }
            }
        });
        let open = async |path: &str| {
            let mut s = relay.open_request().await?;
            s.send(Frame::RequestHead(RequestHead {
                method: "GET".to_owned(),
                path: path.to_owned(),
                query: None,
                headers: vec![],
                attested: AttestedMeta::default(),
            }))
            .await?;
            Ok::<_, ProtoError>(s)
        };
        let ping = async || {
            let mut s = open("/ping").await?;
            match s.recv().await? {
                Some(Frame::ResponseHead(h)) if h.status == 200 => Ok(()),
                other => Err(ProtoError::Protocol(format!("unexpected frame {other:?}"))),
            }
        };

        for _ in 0..RELAY_MAX_REQUESTS + 100 {
            drop(open("/slow").await.unwrap());
        }
        ping().await.expect("the session still serves");

        let mut kept = Vec::new();
        let refused = loop {
            match open("/hold").await {
                Ok(mut s) => {
                    assert!(matches!(s.recv().await, Ok(Some(Frame::ResponseHead(_)))));
                    kept.push(s);
                }
                Err(e) => break e,
            }
        };
        assert!(matches!(refused, ProtoError::Busy), "{refused}");
        assert_eq!(kept.len(), RELAY_MAX_REQUESTS);
        assert!(!relay.is_closed(), "a refused request leaves the session");
        kept.pop();
        ping().await.expect("a freed place serves again");
    }

    /// The agent acknowledges a request stream when it takes it, not with
    /// its answer. yamux stops opening streams while 256 of them wait for
    /// an acknowledgement, so requests the gateway is slow to answer would
    /// otherwise hold up every open past the 256th, below the relay's own
    /// limit, until an earlier answer came.
    #[tokio::test]
    async fn unanswered_streams_never_hold_up_the_next_open() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (agent_res, relay_res) = tokio::join!(
            AgentSession::connect(client_io, HandshakeRequest::new("inst-1", private_spec())),
            RelaySession::accept(server_io, ok_handshake),
        );
        let (mut agent, _resp) = agent_res.unwrap();
        let (relay, _req) = relay_res.unwrap();
        tokio::spawn(async move {
            let mut unanswered = Vec::new();
            while let Some(s) = agent.accept().await {
                unanswered.push(s);
            }
        });

        let mut open = Vec::new();
        while open.len() < RELAY_MAX_REQUESTS {
            let mut s = tokio::time::timeout(Duration::from_secs(5), relay.open_request())
                .await
                .unwrap_or_else(|_| panic!("open {} is held up", open.len() + 1))
                .unwrap();
            s.send(Frame::RequestHead(RequestHead {
                method: "POST".to_owned(),
                path: "/mcp".to_owned(),
                query: None,
                headers: vec![],
                attested: AttestedMeta::default(),
            }))
            .await
            .unwrap();
            open.push(s);
        }
        assert!(matches!(relay.open_request().await, Err(ProtoError::Busy)));
        assert!(!relay.is_closed());
    }

    #[tokio::test]
    async fn relay_rejection_surfaces_to_agent() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        tokio::spawn(async move {
            // Relay refuses every handshake with a quota error.
            let res = RelaySession::accept(server_io, async |_req| {
                Err(ProtoError::Rejected("quota_exceeded".to_owned()))
            })
            .await;
            assert!(res.is_err());
        });

        let err =
            match AgentSession::connect(client_io, HandshakeRequest::new("inst-1", private_spec()))
                .await
            {
                Ok(_) => panic!("handshake must be rejected"),
                Err(e) => e,
            };
        assert!(matches!(err, ProtoError::Rejected(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn agent_rejects_public_e2ee_before_dialing() {
        let (client_io, _server_io) = tokio::io::duplex(1024);
        let bad = TunnelSpec {
            name: None,
            exposure: Exposure::Public,
            mode: TrustMode::E2ee,
        };
        let err = match AgentSession::connect(client_io, HandshakeRequest::new("inst-1", bad)).await
        {
            Ok(_) => panic!("public+e2ee must be refused locally"),
            Err(e) => e,
        };
        assert!(matches!(err, ProtoError::InvalidSpec(_)));
    }
}
