//! The HTTP request/response shapes carried over a tunnel stream. One mux
//! stream carries one MCP request: a [`RequestHead`], then body chunks,
//! then a [`ResponseHead`] and its body chunks in reply.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Metadata about the real client that the **relay attests** — it is derived
/// from the relay's own view of the public connection, never copied from
/// client-supplied headers. The gateway agent maps these onto request
/// extensions (`ConnectInfo`, `TlsInfo`) so the gateway's identity and
/// rate-limit chain sees the true origin. Trusting a client-forwarded value
/// here would reintroduce the spoofing class the gateway's `trust_proxy_ip`
/// / `trust_subject_header` floors exist to prevent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedMeta {
    /// The public peer address as seen by the relay. Drives the gateway's
    /// per-IP anonymous rate limiter; if absent the gateway must treat the
    /// request as un-attributable (limit or reject), never skip the limiter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsMeta>,
}

/// The essentials of the client's TLS session, mirroring the fields the
/// gateway's `TlsInfo` needs to run mTLS identity plugins. Kept independent
/// of `mcpg-plugin-protocol` so neither the relay nor this crate takes that
/// dependency; the gateway agent performs the mapping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    pub client_cert_present: bool,
    /// SHA-256 (hex) of the presented client-cert chain, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_chain_sha256: Option<String>,
    /// SAN URIs from the client cert (e.g. SPIFFE ids), if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub san_uris: Vec<String>,
}

/// The head of a request forwarded down the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// Header name/value pairs. The relay strips hop-by-hop identity and
    /// forwarding headers before populating this, re-attesting origin facts
    /// via [`AttestedMeta`] instead.
    pub headers: Vec<(String, String)>,
    pub attested: AttestedMeta,
}

/// The head of the response returned up the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}
