//! A [`tokio_util::codec`] adapter over [`Frame`], so a mux stream can be
//! wrapped in a `Framed` that yields/accepts whole frames.

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::ProtoError;
use crate::frame::Frame;

/// Delegates to [`Frame::decode`] / [`Frame::encode`]. Stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrameCodec;

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = ProtoError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, ProtoError> {
        Frame::decode(src)
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = ProtoError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), ProtoError> {
        item.encode(dst)
    }
}
