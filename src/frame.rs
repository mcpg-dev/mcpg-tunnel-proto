//! The length-prefixed frame codec.
//!
//! Wire format of one frame: `[kind: u8][len: u32 big-endian][payload: len]`.
//! Structured frames carry JSON payloads; [`Frame::BodyChunk`] carries raw
//! bytes so request/response bodies (including SSE streams) pass through
//! without a serialization copy. The codec is transport- and mux-agnostic:
//! it operates on a `BytesMut` buffer, so the session layer can drive it
//! over a yamux stream, a WebSocket, or an in-memory pipe in tests.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::error::ProtoError;
use crate::handshake::{HandshakeRequest, HandshakeResponse};
use crate::http::{RequestHead, ResponseHead};

/// Hard cap on a single frame's payload. A remote peer must never be able to
/// make us allocate an unbounded buffer from one length prefix; bodies larger
/// than this stream as multiple [`Frame::BodyChunk`]s.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

const KIND_HANDSHAKE_REQUEST: u8 = 0x10;
const KIND_HANDSHAKE_RESPONSE: u8 = 0x11;
const KIND_REQUEST_HEAD: u8 = 0x01;
const KIND_RESPONSE_HEAD: u8 = 0x02;
const KIND_BODY_CHUNK: u8 = 0x03;
const KIND_BODY_END: u8 = 0x04;
const KIND_ERROR: u8 = 0x05;

const HEADER_LEN: usize = 1 + 4; // kind byte + u32 length

/// An in-band error surfaced to the peer as a frame (distinct from a local
/// [`ProtoError`]). Carries a stable machine `code` plus a human `message`,
/// e.g. an auth or quota refusal from the relay, or a mid-stream upstream
/// failure from the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelError {
    pub code: String,
    pub message: String,
}

impl TunnelError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// One protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    HandshakeRequest(HandshakeRequest),
    HandshakeResponse(HandshakeResponse),
    RequestHead(RequestHead),
    ResponseHead(ResponseHead),
    BodyChunk(Bytes),
    BodyEnd,
    Error(TunnelError),
}

impl Frame {
    fn kind(&self) -> u8 {
        match self {
            Frame::HandshakeRequest(_) => KIND_HANDSHAKE_REQUEST,
            Frame::HandshakeResponse(_) => KIND_HANDSHAKE_RESPONSE,
            Frame::RequestHead(_) => KIND_REQUEST_HEAD,
            Frame::ResponseHead(_) => KIND_RESPONSE_HEAD,
            Frame::BodyChunk(_) => KIND_BODY_CHUNK,
            Frame::BodyEnd => KIND_BODY_END,
            Frame::Error(_) => KIND_ERROR,
        }
    }

    fn payload(&self) -> Result<Bytes, ProtoError> {
        Ok(match self {
            Frame::HandshakeRequest(v) => serde_json::to_vec(v)?.into(),
            Frame::HandshakeResponse(v) => serde_json::to_vec(v)?.into(),
            Frame::RequestHead(v) => serde_json::to_vec(v)?.into(),
            Frame::ResponseHead(v) => serde_json::to_vec(v)?.into(),
            Frame::Error(v) => serde_json::to_vec(v)?.into(),
            Frame::BodyChunk(b) => b.clone(),
            Frame::BodyEnd => Bytes::new(),
        })
    }

    /// Append the encoded frame to `dst`.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtoError> {
        let payload = self.payload()?;
        let len: u32 = payload
            .len()
            .try_into()
            .ok()
            .filter(|&l| l <= MAX_FRAME_LEN)
            .ok_or(ProtoError::FrameTooLarge {
                len: payload.len() as u32,
                max: MAX_FRAME_LEN,
            })?;
        dst.reserve(HEADER_LEN + payload.len());
        dst.put_u8(self.kind());
        dst.put_u32(len);
        dst.put_slice(&payload);
        Ok(())
    }

    /// Convenience: encode a single frame to a fresh [`Bytes`].
    pub fn to_bytes(&self) -> Result<Bytes, ProtoError> {
        let mut buf = BytesMut::new();
        self.encode(&mut buf)?;
        Ok(buf.freeze())
    }

    /// Try to decode one frame from the front of `src`. Returns `Ok(None)`
    /// when `src` does not yet hold a complete frame (the caller should read
    /// more bytes and retry); consumes the frame's bytes from `src` only when
    /// a whole frame is returned.
    pub fn decode(src: &mut BytesMut) -> Result<Option<Frame>, ProtoError> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }
        // Peek the length prefix without consuming, so an incomplete frame
        // leaves `src` untouched for the next read.
        let len = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
        if len > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge {
                len,
                max: MAX_FRAME_LEN,
            });
        }
        let total = HEADER_LEN + len as usize;
        if src.len() < total {
            return Ok(None);
        }
        let kind = src[0];
        src.advance(HEADER_LEN);
        let payload = src.split_to(len as usize).freeze();
        let frame = match kind {
            KIND_HANDSHAKE_REQUEST => Frame::HandshakeRequest(serde_json::from_slice(&payload)?),
            KIND_HANDSHAKE_RESPONSE => Frame::HandshakeResponse(serde_json::from_slice(&payload)?),
            KIND_REQUEST_HEAD => Frame::RequestHead(serde_json::from_slice(&payload)?),
            KIND_RESPONSE_HEAD => Frame::ResponseHead(serde_json::from_slice(&payload)?),
            KIND_BODY_CHUNK => Frame::BodyChunk(payload),
            KIND_BODY_END => Frame::BodyEnd,
            KIND_ERROR => Frame::Error(serde_json::from_slice(&payload)?),
            other => return Err(ProtoError::UnknownKind(other)),
        };
        Ok(Some(frame))
    }
}
