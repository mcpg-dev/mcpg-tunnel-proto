//! Error types for tunnel-proto.

/// A local protocol error raised while encoding or decoding frames, or
/// while validating a handshake. Distinct from [`crate::TunnelError`], which
/// is an *in-band* error carried to the peer as a frame.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// A frame's declared payload length exceeds the codec's hard cap. A
    /// remote peer must never be able to make us allocate an unbounded
    /// buffer from a single length prefix.
    #[error("frame payload too large: {len} bytes (max {max})")]
    FrameTooLarge { len: u32, max: u32 },

    /// The leading kind byte does not map to a known frame variant.
    #[error("unknown frame kind byte: 0x{0:02x}")]
    UnknownKind(u8),

    /// A structured (JSON-carrying) frame failed to (de)serialize.
    #[error("frame payload (de)serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    /// The two endpoints could not agree on a protocol version.
    #[error("tunnel protocol version mismatch: agent {agent}, relay {relay}")]
    VersionMismatch { agent: String, relay: String },

    /// A [`crate::TunnelSpec`] violated an invariant (e.g. `e2ee` trust
    /// requested on a `public` tunnel — see [`crate::TunnelSpec::validate`]).
    #[error("invalid tunnel spec: {0}")]
    InvalidSpec(String),

    /// Underlying transport / stream I/O failed. Also lets `ProtoError`
    /// satisfy the `From<io::Error>` bound the tokio-util `Decoder` requires.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The mux session was closed while an operation was in flight (the peer
    /// hung up, or the local session handle was dropped).
    #[error("tunnel session closed")]
    SessionClosed,

    /// The relay refused the handshake (bad spec, quota, entitlement, or auth).
    /// Carries the relay's in-band error code + message.
    #[error("tunnel handshake rejected: {0}")]
    Rejected(String),

    /// A peer violated the frame protocol — an out-of-order or malformed frame
    /// (e.g. a body chunk before a head, or an unparseable HTTP method/header).
    #[error("tunnel protocol violation: {0}")]
    Protocol(String),
}
