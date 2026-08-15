//! Wire protocol for the MCPG reverse tunnel.
//!
//! The tunnel carries **HTTP request/response semantics over a multiplexed
//! byte session**: a self-hosted gateway dials out to the `mcpg-cloud-relay`,
//! the relay forwards each inbound MCP request as a framed request down one
//! mux stream, and the gateway answers it through its own full request path
//! (`router().oneshot(..)`), streaming the response back on the same stream.
//!
//! Layers, transport- and mux-agnostic:
//!
//! - [`handshake`] — the one-time session establishment: [`TunnelSpec`]
//!   ([`Exposure`] × [`TrustMode`]), version [`negotiate`]iation.
//! - [`frame`] — the length-prefixed [`Frame`] codec ([`RequestHead`],
//!   [`ResponseHead`], [`Frame::BodyChunk`], …) over a `BytesMut` buffer.
//! - `session` (feature `session`, default on) — the yamux mux driver over
//!   any `AsyncRead + AsyncWrite` transport, with the asymmetric
//!   agent/relay roles. Disable the feature (`default-features = false`)
//!   for a pure, dep-light types-only build; the relay and the
//!   gateway-side agent are built on it.

pub mod error;
pub mod frame;
pub mod handshake;
pub mod http;

#[cfg(feature = "session")]
pub mod codec;
#[cfg(feature = "session")]
pub mod session;

pub use error::ProtoError;
pub use frame::{Frame, MAX_FRAME_LEN, TunnelError};
pub use handshake::{
    Exposure, HandshakeRequest, HandshakeResponse, TUNNEL_PROTO_VERSION, TrustMode, TunnelSpec,
    negotiate,
};
pub use http::{AttestedMeta, RequestHead, ResponseHead, TlsMeta};

#[cfg(feature = "session")]
pub use codec::FrameCodec;
#[cfg(feature = "session")]
pub use session::{AgentSession, FrameStream, RelaySession};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, Bytes, BytesMut};
    use std::net::{IpAddr, Ipv4Addr};

    fn spec(exposure: Exposure, mode: TrustMode) -> TunnelSpec {
        TunnelSpec {
            name: Some("acme-crm".to_owned()),
            exposure,
            mode,
        }
    }

    /// Encode a frame, then decode it back out of a buffer and assert equality.
    fn round_trip(frame: Frame) {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).expect("encode");
        let decoded = Frame::decode(&mut buf)
            .expect("decode ok")
            .expect("a frame");
        assert_eq!(frame, decoded);
        assert!(buf.is_empty(), "decode must consume exactly one frame");
    }

    #[test]
    fn round_trip_handshake_request() {
        round_trip(Frame::HandshakeRequest(HandshakeRequest::new(
            "inst-123",
            spec(Exposure::Private, TrustMode::E2ee),
        )));
    }

    #[test]
    fn round_trip_handshake_response_public_and_private() {
        round_trip(Frame::HandshakeResponse(HandshakeResponse {
            accepted_proto_version: TUNNEL_PROTO_VERSION.to_owned(),
            tunnel_id: "acme-crm-7f3a".to_owned(),
            public_url: Some("https://acme-crm-7f3a.tunnels.mcpg.cloud/mcp".to_owned()),
            heartbeat_secs: 30,
        }));
        // Private tunnels carry no public URL.
        round_trip(Frame::HandshakeResponse(HandshakeResponse {
            accepted_proto_version: TUNNEL_PROTO_VERSION.to_owned(),
            tunnel_id: "acme-crm-7f3a".to_owned(),
            public_url: None,
            heartbeat_secs: 30,
        }));
    }

    #[test]
    fn round_trip_request_head_with_attested_origin() {
        round_trip(Frame::RequestHead(RequestHead {
            method: "POST".to_owned(),
            path: "/mcp".to_owned(),
            query: None,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            attested: AttestedMeta {
                client_ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
                tls: Some(TlsMeta {
                    sni: Some("acme-crm-7f3a.tunnels.mcpg.cloud".to_owned()),
                    client_cert_present: true,
                    client_cert_chain_sha256: Some("abcd".to_owned()),
                    san_uris: vec!["spiffe://mcpg/instance/inst-123".to_owned()],
                }),
            },
        }));
    }

    #[test]
    fn round_trip_response_body_stream_and_error() {
        round_trip(Frame::ResponseHead(ResponseHead {
            status: 200,
            headers: vec![("content-type".to_owned(), "text/event-stream".to_owned())],
        }));
        round_trip(Frame::BodyChunk(Bytes::from_static(
            b"event: message\ndata: {}\n\n",
        )));
        round_trip(Frame::BodyEnd);
        round_trip(Frame::Error(TunnelError::new(
            "quota_exceeded",
            "tunnel limit reached",
        )));
    }

    #[test]
    fn decode_is_incremental_and_streams_multiple_frames() {
        // Two frames encoded back-to-back decode one at a time; a partial
        // tail yields Ok(None) without consuming or erroring.
        let mut wire = BytesMut::new();
        Frame::BodyChunk(Bytes::from_static(b"one"))
            .encode(&mut wire)
            .unwrap();
        Frame::BodyChunk(Bytes::from_static(b"two"))
            .encode(&mut wire)
            .unwrap();

        // Feed the bytes one at a time; decode yields exactly two frames.
        let full = wire.split().freeze();
        let mut buf = BytesMut::new();
        let mut got = Vec::new();
        for byte in full.iter() {
            buf.put_u8(*byte);
            while let Some(f) = Frame::decode(&mut buf).unwrap() {
                got.push(f);
            }
        }
        assert_eq!(
            got,
            vec![
                Frame::BodyChunk(Bytes::from_static(b"one")),
                Frame::BodyChunk(Bytes::from_static(b"two")),
            ]
        );
    }

    #[test]
    fn decode_partial_header_returns_none() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x03, 0x00]); // kind + 1 of 4 length bytes
        assert!(Frame::decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 2, "an incomplete frame is left untouched");
    }

    #[test]
    fn decode_rejects_unknown_kind() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(
            Frame::decode(&mut buf),
            Err(ProtoError::UnknownKind(0xFF))
        ));
    }

    #[test]
    fn decode_rejects_oversized_length_prefix() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x03);
        buf.put_u32(MAX_FRAME_LEN + 1);
        assert!(matches!(
            Frame::decode(&mut buf),
            Err(ProtoError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn spec_validate_rejects_public_e2ee() {
        assert!(spec(Exposure::Private, TrustMode::E2ee).validate().is_ok());
        assert!(
            spec(Exposure::Private, TrustMode::RelayTerminated)
                .validate()
                .is_ok()
        );
        assert!(
            spec(Exposure::Public, TrustMode::RelayTerminated)
                .validate()
                .is_ok()
        );
        // The one forbidden combination.
        assert!(matches!(
            spec(Exposure::Public, TrustMode::E2ee).validate(),
            Err(ProtoError::InvalidSpec(_))
        ));
    }

    #[test]
    fn version_negotiation_matches_major_only() {
        assert_eq!(negotiate("1.0", "1.3").unwrap(), "1.3");
        assert_eq!(negotiate("1.9", "1.0").unwrap(), "1.0");
        assert!(matches!(
            negotiate("1.0", "2.0"),
            Err(ProtoError::VersionMismatch { .. })
        ));
    }
}
