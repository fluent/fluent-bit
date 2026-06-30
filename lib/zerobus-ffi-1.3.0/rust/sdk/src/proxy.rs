use std::sync::Arc;

use hyper_http_proxy::{Intercept, Proxy, ProxyConnector as HyperProxyConnector};
use hyper_util::client::legacy::connect::HttpConnector;
use tracing::info;

use crate::ZerobusError;

pub(crate) type ProxiedConnector = HyperProxyConnector<HttpConnector>;

/// A proxy connector for the gRPC channel.
///
/// Construct with [`ProxyConnector::new`] and install via
/// [`crate::ZerobusSdkBuilder::connector_factory`] to override the SDK's
/// default env-var proxy detection.
///
/// Supports both `http://` and `https://` proxy URIs — for HTTPS proxies, the
/// client→proxy hop does a TLS handshake using the system trust store, and
/// the CONNECT tunnel still carries raw TCP so tonic can layer its own TLS on
/// top of the target endpoint.
pub struct ProxyConnector(ProxiedConnector);

impl ProxyConnector {
    /// Build a proxy connector that routes all gRPC traffic through
    /// `proxy_uri` (e.g. `"http://corp-proxy:3128"` or
    /// `"https://corp-proxy:3128"`).
    #[allow(clippy::result_large_err)]
    pub fn new(proxy_uri: &str) -> Result<Self, ZerobusError> {
        build_connector(proxy_uri).map(Self)
    }

    pub(crate) fn into_inner(self) -> ProxiedConnector {
        self.0
    }
}

#[allow(clippy::result_large_err)]
fn build_connector(proxy_uri: &str) -> Result<ProxiedConnector, ZerobusError> {
    let uri = proxy_uri.parse().map_err(|e| {
        ZerobusError::InvalidArgument(format!("failed to parse proxy URL '{}': {}", proxy_uri, e))
    })?;
    let mut proxy = Proxy::new(Intercept::All, uri);
    // gRPC is HTTP/2 and cannot traverse a regular HTTP/1 forward proxy;
    // force CONNECT tunneling for all targets (matches gRPC core behavior).
    proxy.force_connect();
    let mut http_connector = HttpConnector::new();
    // Allow non-http target schemes (e.g. https:// CONNECT targets) through
    // the underlying TCP connector; without this, HttpConnector rejects them.
    http_connector.enforce_http(false);
    // `from_proxy` (vs `from_proxy_unsecured`) attaches a TLS connector used
    // only for the client→proxy hop when the proxy URL is https://. The
    // CONNECT tunnel still carries raw TCP; tonic applies its own TLS to the
    // target endpoint on top.
    HyperProxyConnector::from_proxy(http_connector, proxy).map_err(|e| {
        ZerobusError::ChannelCreationError(format!("failed to build proxy connector: {}", e))
    })
}

/// Signature for caller-supplied proxy selection. Given the target host,
/// return a configured connector or `None` for a direct connection.
///
/// Set via [`crate::ZerobusSdkBuilder::connector_factory`]. When a factory is
/// installed it fully replaces the default env-var proxy detection — callers
/// own the complete proxy decision, including any no-proxy bypass rules.
pub type ConnectorFactory = Arc<dyn Fn(&str) -> Option<ProxyConnector> + Send + Sync>;

/// Env var names checked for proxy URL, in gRPC core precedence order.
const PROXY_ENV_VARS: &[&str] = &[
    "grpc_proxy",
    "GRPC_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "http_proxy",
    "HTTP_PROXY",
];

/// Env var names checked for no-proxy list, in gRPC core precedence order.
const NO_PROXY_ENV_VARS: &[&str] = &["no_grpc_proxy", "NO_GRPC_PROXY", "no_proxy", "NO_PROXY"];

/// Reads the first non-empty value from the given env var names.
fn read_first_env(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(val) = std::env::var(name) {
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Reads proxy environment variables and returns a `ProxiedConnector`
/// if one is configured, or `None` for direct connections.
///
/// Follows gRPC core precedence: `grpc_proxy` → `https_proxy` → `http_proxy`.
/// For each name the lowercase variant is checked first, then uppercase
/// (matching standard convention and gRPC core behavior).
///
/// Uses `from_proxy` so `https://` proxy URLs work (TLS handshake on the
/// client→proxy hop using the system trust store). The CONNECT tunnel still
/// carries raw TCP; tonic applies TLS to the target on top.
pub(crate) fn create_proxy_connector() -> Option<ProxiedConnector> {
    let proxy_url = read_first_env(PROXY_ENV_VARS)?;
    info!("Using HTTP proxy: {}", proxy_url);
    match build_connector(&proxy_url) {
        Ok(pc) => Some(pc),
        Err(e) => {
            tracing::warn!("{}", e);
            None
        }
    }
}

/// Checks whether a given host should bypass the proxy.
///
/// Follows gRPC core precedence: `no_grpc_proxy` → `no_proxy`.
/// For each name the lowercase variant is checked first, then uppercase.
/// A wildcard `*` matches all hosts. Otherwise entries are matched as
/// suffix of the target host (e.g. `example.com` matches `foo.example.com`).
pub(crate) fn is_no_proxy(host: &str) -> bool {
    let no_proxy = read_first_env(NO_PROXY_ENV_VARS).unwrap_or_default();
    host_matches_no_proxy(host, &no_proxy)
}

/// Pure logic for no-proxy matching, separated for testability.
fn host_matches_no_proxy(host: &str, no_proxy: &str) -> bool {
    if no_proxy.is_empty() {
        return false;
    }

    if no_proxy.trim() == "*" {
        return true;
    }

    no_proxy.split(',').any(|entry| {
        let entry = entry.trim().trim_start_matches('.');
        host == entry || host.ends_with(&format!(".{}", entry))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_empty_returns_false() {
        assert!(!host_matches_no_proxy("example.com", ""));
    }

    #[test]
    fn no_proxy_wildcard_matches_everything() {
        assert!(host_matches_no_proxy("anything.com", "*"));
        assert!(host_matches_no_proxy("localhost", " * "));
    }

    #[test]
    fn no_proxy_exact_match() {
        assert!(host_matches_no_proxy("example.com", "example.com"));
        assert!(!host_matches_no_proxy("other.com", "example.com"));
    }

    #[test]
    fn no_proxy_suffix_match() {
        assert!(host_matches_no_proxy(
            "workspace.cloud.databricks.com",
            "databricks.com"
        ));
        assert!(host_matches_no_proxy("foo.example.com", "example.com"));
        // Must be a subdomain, not just a string suffix
        assert!(!host_matches_no_proxy("notexample.com", "example.com"));
    }

    #[test]
    fn no_proxy_leading_dot_stripped() {
        assert!(host_matches_no_proxy("foo.example.com", ".example.com"));
        assert!(host_matches_no_proxy("example.com", ".example.com"));
    }

    #[test]
    fn no_proxy_comma_separated() {
        let no_proxy = "localhost, 127.0.0.1, .internal.corp";
        assert!(host_matches_no_proxy("localhost", no_proxy));
        assert!(host_matches_no_proxy("127.0.0.1", no_proxy));
        assert!(host_matches_no_proxy("service.internal.corp", no_proxy));
        assert!(!host_matches_no_proxy("external.com", no_proxy));
    }

    #[test]
    fn no_proxy_whitespace_handling() {
        assert!(host_matches_no_proxy("example.com", "  example.com  "));
        assert!(host_matches_no_proxy(
            "example.com",
            "other.com , example.com , more.com"
        ));
    }
}
