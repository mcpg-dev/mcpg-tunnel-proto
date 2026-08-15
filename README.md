# mcpg-tunnel-proto

> Wire protocol for the MCPG reverse tunnel: frames, handshake, and the yamux session layer.

The MCPG reverse tunnel carries HTTP request/response semantics over a
multiplexed byte session. A self-hosted gateway dials **out** to a relay, the
relay forwards each inbound MCP request as framed bytes down one mux stream,
and the gateway answers through its own full request path — no inbound port,
no public listener on the gateway side. This crate owns that wire: the frame
codec, the session handshake and its version negotiation, and the yamux mux
driver with its asymmetric agent/relay roles. It is transport-agnostic and
holds no networking policy — it does not dial, authenticate, meter, or route.

## What's here

- `frame` — the length-prefixed codec. One frame is
  `[kind: u8][len: u32 big-endian][payload]`. `Frame::encode` appends to a
  `BytesMut`; `Frame::decode` pulls one frame off the front and returns
  `Ok(None)` when the buffer does not yet hold a whole one, leaving the partial
  bytes untouched. Variants: `HandshakeRequest`, `HandshakeResponse`,
  `RequestHead`, `ResponseHead`, `BodyChunk`, `BodyEnd`, `Error(TunnelError)`.
  Structured frames carry JSON; `BodyChunk` carries raw bytes so bodies —
  including SSE streams — pass through without a serialization copy.
- `MAX_FRAME_LEN` — a hard 16 MiB cap on one frame's payload, checked against
  the length prefix *before* any allocation, so a peer cannot force an
  unbounded buffer from a single header. Larger bodies stream as multiple
  `BodyChunk`s.
- `handshake` — `TunnelSpec` (`Exposure` × `TrustMode`), `HandshakeRequest`,
  `HandshakeResponse`, `TUNNEL_PROTO_VERSION`, and `negotiate`.
- `http` — `RequestHead`, `ResponseHead`, and the relay-attested origin
  metadata `AttestedMeta` / `TlsMeta`.
- `error` — `ProtoError`, the local encode/decode/validate error, distinct from
  `TunnelError`, which is an *in-band* error delivered to the peer as a frame.
- `codec::FrameCodec` (feature `session`) — a stateless `tokio_util::codec`
  `Encoder`/`Decoder` over `Frame`.
- `session` (feature `session`) — `AgentSession`, `RelaySession`, and
  `FrameStream`, the yamux driver over any `AsyncRead + AsyncWrite` transport.

## Session model

Roles are fixed and asymmetric. The **agent** dials out, opens the single
control stream, sends its handshake, and then *accepts* the request streams the
relay opens. The **relay** accepts the connection and the control stream,
applies its own policy in an async `on_handshake` callback — spec validity,
auth, quota, entitlement — and then *opens* one request stream per inbound
public request. Each request stream carries exactly one exchange: a
`RequestHead`, body chunks, `BodyEnd`, then a `ResponseHead` with its own body
chunks and `BodyEnd`.

A rejected handshake is answered with an in-band `Frame::Error` before the
session is torn down, so the dialing agent learns why rather than seeing a bare
disconnect. Session shutdown is a graceful yamux close rather than an abort,
precisely so that final frame is flushed instead of racing the teardown.
`RelaySession::closed()` hands back a `watch::Receiver` that resolves once the
connection ends, so a relay can retire a dead tunnel promptly instead of
waiting for lazy eviction.

## Exposure and trust

`TunnelSpec::validate` enforces one cross-field invariant, and both endpoints
call it — the agent before dialing, the relay on handshake — so a malformed
spec is refused at the earliest possible point.

| Field | Values | Meaning |
|---|---|---|
| `exposure` | `public` | A public hostname is allocated and TLS terminates at the relay. |
| `exposure` | `private` | No hostname, cert, or DNS is allocated; reachable only as a federation upstream from a same-org gateway. |
| `mode` | `relay_terminated` | The relay terminates client TLS and sees plaintext. Required when the consumer is a third-party MCP client. |
| `mode` | `e2ee` | Both endpoints run an inner encrypted session through the relay, which splices ciphertext. |

`e2ee` with `public` exposure is rejected: end-to-end encryption is only
meaningful when both ends are MCPG, which is by definition a private tunnel.
A public tunnel has to terminate a third party's TLS at the relay.

`negotiate(agent, relay)` compares the major version component only and returns
the relay's version within that major, so additive minors stay
forward-compatible; a major mismatch is a `ProtoError::VersionMismatch`.

## Attested origin

`AttestedMeta` carries what the **relay observes** about the real client — the
public peer address in `client_ip`, and `TlsMeta` (`sni`,
`client_cert_present`, `client_cert_chain_sha256`, `san_uris`) for the client's
TLS session. These are derived from the relay's own view of the public
connection and are never copied from client-supplied headers; the relay strips
hop-by-hop identity and forwarding headers from `RequestHead::headers` and
re-attests the origin here instead. Trusting a client-forwarded value would
reintroduce exactly the spoofing class a gateway's proxy-trust settings exist to
prevent. `client_ip` is the input a consumer's per-IP rate limiter keys on, so
an agent implementation should carry it onto the replayed request rather than
letting the request arrive with no attributable origin.

`TlsMeta` mirrors only the fields a gateway needs and stays independent of the
plugin protocol, so neither this crate nor a relay takes that dependency; the
mapping onto gateway request extensions happens in `mcpg-tunnel-agent`.

## Used by

- `mcpg-tunnel-agent` — the gateway-side request engine built on
  `AgentSession`.
- `apps/gateway` — dials a relay and serves tunnelled MCP traffic.
- The managed relay broker, built on `RelaySession` — operated as a hosted
  service and not part of this repository.

## Features

| Feature | Default | Effect |
|---|---|---|
| `session` | on | Adds `codec` and `session`: the `tokio-util` frame codec and the yamux mux driver (`tokio`, `tokio-util`, `yamux`, `futures`). |

Build with `default-features = false` for a dep-light, types-only crate — the
frames, handshake, HTTP shapes, and errors, with no async runtime.

## Usage

The crate is not published to crates.io; depend on it by path from within this
workspace.

```toml
[dependencies]
mcpg-tunnel-proto = { path = "../tunnel-proto" }
```

```rust
use mcpg_tunnel_proto::{
    AgentSession, Exposure, HandshakeRequest, TrustMode, TunnelSpec,
};

let spec = TunnelSpec {
    name: Some("acme-crm".to_owned()),
    exposure: Exposure::Private,
    mode: TrustMode::RelayTerminated,
};
spec.validate()?;

// `transport` is any AsyncRead + AsyncWrite — a TLS WebSocket in
// production, an in-memory duplex in tests.
let (mut session, resp) =
    AgentSession::connect(transport, HandshakeRequest::new("inst-123", spec)).await?;

while let Some(stream) = session.accept().await {
    // one MCP request/response exchange per stream
}
```

The crate targets Rust edition 2024.

## Build / test

```bash
cargo build -p mcpg-tunnel-proto
cargo test  -p mcpg-tunnel-proto
cargo test  -p mcpg-tunnel-proto --no-default-features   # types-only build
```

## Licence

Apache-2.0.

## See also

- [Tunneling](https://mcpg.dev/docs/gateway/tunneling)
- [Reverse federation](https://mcpg.dev/articles/reverse-federation)
- `libs/tunnel-agent` — the agent-side request engine built on this protocol.
