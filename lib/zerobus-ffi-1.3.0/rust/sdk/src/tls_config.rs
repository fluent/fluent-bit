//! TLS configuration for Zerobus connections.
//!
//! This module provides a strategy pattern for TLS configuration,
//! allowing different TLS setups (secure, custom CA, or no TLS for testing).

use crate::errors::ZerobusError;
use crate::ZerobusResult;
use tonic::transport::{ClientTlsConfig, Endpoint};

/// Trait for TLS configuration strategies.
///
/// Implementations define how to configure the gRPC channel's TLS settings.
/// This allows the SDK to support different TLS configurations:
/// - `SecureTlsConfig`: Production TLS with system CA certificates (default)
/// - `NoTlsConfig`: No TLS, for testing with local `http://` endpoints (requires `testing` feature)
/// - Custom implementations for special certificate requirements
///
/// # Examples
///
/// ```rust
/// use databricks_zerobus_ingest_sdk::{SecureTlsConfig, TlsConfig};
/// use std::sync::Arc;
///
/// // Secure TLS with system CAs (default)
/// let tls: Arc<dyn TlsConfig> = Arc::new(SecureTlsConfig::new());
/// ```
#[allow(clippy::result_large_err)]
pub trait TlsConfig: Send + Sync {
    /// Configure a gRPC endpoint with TLS settings.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The gRPC endpoint to configure
    ///
    /// # Returns
    ///
    /// The configured endpoint, ready to connect
    ///
    /// # Errors
    ///
    /// Returns an error if TLS configuration fails
    fn configure_endpoint(&self, endpoint: Endpoint) -> ZerobusResult<Endpoint>;
}

/// Secure TLS configuration using system CA certificates.
///
/// This is the default and recommended configuration for production use.
/// It enables TLS encryption using the operating system's trusted CA certificates.
///
/// # Examples
///
/// ```rust
/// use databricks_zerobus_ingest_sdk::SecureTlsConfig;
///
/// let tls = SecureTlsConfig::new();
/// ```
#[derive(Clone, Debug, Default)]
pub struct SecureTlsConfig;

impl SecureTlsConfig {
    /// Create a new secure TLS configuration.
    pub fn new() -> Self {
        Self
    }
}

impl TlsConfig for SecureTlsConfig {
    fn configure_endpoint(&self, endpoint: Endpoint) -> ZerobusResult<Endpoint> {
        // Use native OS certificate store (works on Windows, macOS, and Linux).
        let tls_config = ClientTlsConfig::new().with_native_roots();

        endpoint
            .tls_config(tls_config)
            .map_err(|_| ZerobusError::FailedToEstablishTlsConnectionError)
    }
}

/// No-op TLS configuration for testing with plaintext `http://` endpoints.
///
/// This passes the endpoint through without any TLS configuration.
/// Only available when the `testing` feature is enabled.
///
/// # Examples
///
/// ```rust
/// use databricks_zerobus_ingest_sdk::{NoTlsConfig, TlsConfig};
/// use std::sync::Arc;
///
/// let tls: Arc<dyn TlsConfig> = Arc::new(NoTlsConfig);
/// ```
#[cfg(feature = "testing")]
#[derive(Clone, Debug, Default)]
pub struct NoTlsConfig;

#[cfg(feature = "testing")]
impl TlsConfig for NoTlsConfig {
    fn configure_endpoint(&self, endpoint: Endpoint) -> ZerobusResult<Endpoint> {
        Ok(endpoint)
    }
}
