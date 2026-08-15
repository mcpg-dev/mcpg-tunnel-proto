//! Session handshake: the one-time control exchange that establishes a
//! tunnel and negotiates the protocol version, before any request streams
//! flow.

use serde::{Deserialize, Serialize};

use crate::error::ProtoError;

/// The protocol version this crate speaks. Bumped independently of the
/// frozen internal ABI/plugin-protocol versions — this is a NEW external
/// wire whose compatibility obligations begin at its first
/// public release, so it carries its own semantic version.
pub const TUNNEL_PROTO_VERSION: &str = "1.0";

/// Whether a tunnel is reachable from the public internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// A public hostname (`<id>.tunnels.mcpg.cloud`) is allocated and TLS is
    /// terminated at the relay. For dev preview and third-party MCP clients.
    Public,
    /// No public hostname, cert, or DNS is allocated. Reachable *only* as a
    /// `tunnel://<name>` federation upstream from a same-org gateway. The
    /// zero-public-surface posture for secret-sovereign federation.
    Private,
}

/// Who can read the tunnelled payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// The relay terminates the client TLS and sees plaintext (parity with
    /// OpenAI/ngrok). The only option when the consumer is a third-party
    /// MCP client.
    RelayTerminated,
    /// Both endpoints are mcpg and run an inner encrypted session *through*
    /// the relay; the relay splices ciphertext and reads nothing. Requires
    /// [`Exposure::Private`] (mcpg-to-mcpg only).
    E2ee,
}

/// The requested shape of a tunnel, sent by the agent in the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelSpec {
    /// A stable name, or `None` to have the relay allocate one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub exposure: Exposure,
    pub mode: TrustMode,
}

impl TunnelSpec {
    /// Enforce the cross-field invariant: end-to-end
    /// encryption is only meaningful when both endpoints are mcpg, which is
    /// a private (federation-only) tunnel. A public tunnel must terminate a
    /// third-party client's TLS at the relay and therefore cannot be
    /// `e2ee`. Both the agent (pre-dial) and the relay (on handshake) call
    /// this so a malformed spec is refused at the earliest point.
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.mode == TrustMode::E2ee && self.exposure == Exposure::Public {
            return Err(ProtoError::InvalidSpec(
                "e2ee trust requires private exposure (mcpg-to-mcpg only)".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Agent → relay: open a tunnel session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub proto_version: String,
    /// The dialing instance's stable UID, bound to the enrollment token at
    /// Register time so the relay can anti-spoof.
    pub instance_uid: String,
    pub spec: TunnelSpec,
    /// Bearer credential for the standalone `mcpg-tunnel` path. A
    /// CP-attached gateway presents its instance JWT + mTLS via the
    /// transport instead and leaves this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<String>,
}

impl HandshakeRequest {
    pub fn new(instance_uid: impl Into<String>, spec: TunnelSpec) -> Self {
        Self {
            proto_version: TUNNEL_PROTO_VERSION.to_owned(),
            instance_uid: instance_uid.into(),
            spec,
            bearer: None,
        }
    }
}

/// Relay → agent: the tunnel is open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub accepted_proto_version: String,
    /// The allocated tunnel id (`<name>-<nonce>` when the agent left `name`
    /// unset).
    pub tunnel_id: String,
    /// The public URL, present iff [`Exposure::Public`]. `None` for a
    /// private (federation-only) tunnel, which has no public address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    /// How often the agent should send a keepalive on the control channel.
    pub heartbeat_secs: u32,
}

/// Negotiate a protocol version between an agent and a relay. v1 policy:
/// the major component must match exactly; the relay's minor is authoritative
/// within that major (forward-compatible additive minors). Returns the agreed
/// version string or [`ProtoError::VersionMismatch`].
pub fn negotiate(agent: &str, relay: &str) -> Result<String, ProtoError> {
    let major = |v: &str| v.split('.').next().unwrap_or("").to_owned();
    if major(agent) == major(relay) && !major(agent).is_empty() {
        Ok(relay.to_owned())
    } else {
        Err(ProtoError::VersionMismatch {
            agent: agent.to_owned(),
            relay: relay.to_owned(),
        })
    }
}
