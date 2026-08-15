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
use std::pin::Pin;
use std::task::Poll;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};
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
}

impl FrameStream {
    fn new(stream: yamux::Stream) -> Self {
        Self {
            inner: Framed::new(stream.compat(), FrameCodec),
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
    fn spawn<T>(io: T, mode: yamux::Mode) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let conn = yamux::Connection::new(io.compat(), yamux::Config::default(), mode);
        let (open_tx, open_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (closed_tx, closed_rx) = watch::channel(());
        tokio::spawn(drive(conn, open_rx, inbound_tx, shutdown_rx, closed_tx));
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

    async fn accept(&mut self) -> Option<FrameStream> {
        self.inbound_rx.recv().await.map(FrameStream::new)
    }
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
    mut open_rx: mpsc::UnboundedReceiver<OpenReply>,
    inbound_tx: mpsc::UnboundedSender<yamux::Stream>,
    mut shutdown_rx: oneshot::Receiver<()>,
    // Held for the driver's lifetime; dropped when it returns (connection
    // closed), which resolves the `RelaySession::closed` watch receivers.
    _closed_tx: watch::Sender<()>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut pending: VecDeque<OpenReply> = VecDeque::new();
    let mut open_closed = false;
    let mut shutting_down = false;

    loop {
        let keep_going = std::future::poll_fn(|cx| {
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
        let mux = Mux::spawn(io, yamux::Mode::Client);
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
        // Async so the relay's policy can make an authoritative control-plane
        // call (org resolution, quota, suspension, entitlement) and reject
        // in-band before the handshake response is sent.
        F: AsyncFnOnce(&HandshakeRequest) -> Result<HandshakeResponse, ProtoError>,
    {
        let mut mux = Mux::spawn(io, yamux::Mode::Server);
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
            },
            req,
        ))
    }

    /// Open a request stream to the agent (one per inbound public request).
    pub async fn open_request(&self) -> Result<FrameStream, ProtoError> {
        self.mux.open().await
    }

    /// A watch handle that resolves once the tunnel connection closes (peer
    /// hang-up or transport error). The relay's per-tunnel lifecycle task
    /// awaits `changed()` on it to flush final metering and deregister the
    /// tunnel promptly, rather than waiting for lazy eviction on the next
    /// request. Cheap to clone; awaiting a clone never blocks the data path.
    pub fn closed(&self) -> watch::Receiver<()> {
        self.mux.closed_rx.clone()
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
