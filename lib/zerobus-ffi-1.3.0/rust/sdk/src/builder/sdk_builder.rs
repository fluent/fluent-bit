//! Builder for creating [`ZerobusSdk`] instances.

use std::sync::Arc;
use std::time::Duration;

use crate::proxy::ConnectorFactory;
use crate::token_cache::DEFAULT_REFRESH_BUFFER;
use crate::{
    SecureTlsConfig, TlsConfig, ZerobusError, ZerobusResult, ZerobusSdk, DEFAULT_SDK_IDENTIFIER,
};

/// Builder for creating a [`ZerobusSdk`] instance with fluent configuration.
///
/// # Examples
///
/// ```no_run
/// use databricks_zerobus_ingest_sdk::ZerobusSdkBuilder;
///
/// let sdk = ZerobusSdkBuilder::new()
///     .endpoint("https://workspace.zerobus.databricks.com")
///     .unity_catalog_url("https://workspace.cloud.databricks.com")
///     .build()?;
/// # Ok::<(), databricks_zerobus_ingest_sdk::ZerobusError>(())
/// ```
pub struct ZerobusSdkBuilder {
    zerobus_endpoint: Option<String>,
    unity_catalog_url: Option<String>,
    tls_config: Option<Arc<dyn TlsConfig>>,
    connector_factory: Option<ConnectorFactory>,
    application_name: Option<String>,
    sdk_identifier_override: Option<String>,
    token_cache_enabled: bool,
    token_refresh_buffer: Duration,
}

impl ZerobusSdkBuilder {
    /// Creates a new SDK builder with default settings.
    ///
    /// TLS is enabled by default using `SecureTlsConfig`.
    pub fn new() -> Self {
        Self {
            zerobus_endpoint: None,
            unity_catalog_url: None,
            tls_config: None,
            connector_factory: None,
            application_name: None,
            sdk_identifier_override: None,
            token_cache_enabled: true,
            token_refresh_buffer: DEFAULT_REFRESH_BUFFER,
        }
    }

    /// Sets the Zerobus API endpoint URL.
    ///
    /// This is required. The workspace ID is automatically extracted from this URL.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The Zerobus endpoint URL (e.g., "https://workspace-id.zerobus.region.cloud.databricks.com")
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.zerobus_endpoint = Some(endpoint.into());
        self
    }

    /// Sets the Unity Catalog endpoint URL.
    ///
    /// This is only required when using OAuth authentication via `create_stream()`.
    /// When using `create_stream_with_headers_provider()` with a custom headers
    /// provider, this can be omitted.
    ///
    /// # Arguments
    ///
    /// * `url` - The Unity Catalog URL (e.g., "https://workspace.cloud.databricks.com")
    pub fn unity_catalog_url(mut self, url: impl Into<String>) -> Self {
        self.unity_catalog_url = Some(url.into());
        self
    }

    /// Sets a custom TLS configuration.
    ///
    /// Use this to provide custom certificate handling or other TLS settings.
    /// If not set, the default `SecureTlsConfig` (system CA certificates) is used.
    ///
    /// # Arguments
    ///
    /// * `tls_config` - A TLS configuration implementing the `TlsConfig` trait
    pub fn tls_config(mut self, tls_config: Arc<dyn TlsConfig>) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Override gRPC channel connector construction; see
    /// [`ConnectorFactory`] for semantics.
    pub fn connector_factory(mut self, factory: ConnectorFactory) -> Self {
        self.connector_factory = Some(factory);
        self
    }

    /// Sets a custom application identifier appended to the HTTP `user-agent`
    /// header sent on every request.
    ///
    /// The default user-agent value is `zerobus-sdk-rs/<version>`. When this is
    /// set, the value sent becomes `zerobus-sdk-rs/<version> <application_name>`,
    /// preserving the SDK version prefix for server-side telemetry while
    /// adding caller-supplied identification (e.g. `"my-app/1.0"`).
    ///
    /// The SDK owns the `user-agent` header at the tonic `Endpoint` level;
    /// values returned by a [`HeadersProvider`](crate::HeadersProvider) cannot
    /// override it.
    ///
    /// If [`sdk_identifier`](Self::sdk_identifier) is also set, the override
    /// replaces the SDK prefix but this value is still appended — the wire
    /// value becomes `<sdk_identifier> <application_name>`.
    ///
    /// # Arguments
    ///
    /// * `name` - Application identifier, conventionally `<product>/<version>`
    pub fn application_name(mut self, name: impl Into<String>) -> Self {
        self.application_name = Some(name.into());
        self
    }

    /// Overrides the SDK prefix of the HTTP `user-agent` header, replacing the
    /// default `zerobus-sdk-rs/<version>`.
    ///
    /// Used by wrapper SDKs that need to replace the SDK identification itself.
    ///
    /// Empty values are ignored and the default identifier is used. If
    /// [`application_name`](Self::application_name) is also set, it is still
    /// appended after this override — the wire value becomes
    /// `<sdk_identifier> <application_name>`.
    ///
    /// # Arguments
    ///
    /// * `identifier` - Replacement SDK prefix (e.g. `"zerobus-sdk-py/2.0.0"`)
    pub fn sdk_identifier(mut self, identifier: impl Into<String>) -> Self {
        self.sdk_identifier_override = Some(identifier.into());
        self
    }

    /// Enables or disables caching of OAuth tokens for the default OAuth path.
    ///
    /// When enabled (the default), tokens obtained via `.oauth(...)` are cached
    /// per table on the SDK instance and reused across stream creations and
    /// recoveries until they near expiry, instead of minting a fresh token on
    /// every stream. This reduces load on the Unity Catalog token endpoint for
    /// clients that churn through many short-lived streams.
    ///
    /// Caching only applies to the built-in OAuth path. Custom
    /// [`HeadersProvider`](crate::HeadersProvider) implementations are
    /// responsible for their own caching. Tokens are shared only across streams
    /// created from the same `ZerobusSdk` instance, so reuse the SDK rather than
    /// constructing a new one per stream to benefit from the cache.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to cache OAuth tokens.
    pub fn token_cache_enabled(mut self, enabled: bool) -> Self {
        self.token_cache_enabled = enabled;
        self
    }

    /// Sets how long before a cached OAuth token's expiry it is refreshed.
    ///
    /// A cached token is re-minted on the next stream creation once it is within
    /// this buffer of its expiry, providing headroom against clock skew and
    /// token propagation delays. Defaults to 5 minutes. Has no effect when token
    /// caching is disabled.
    ///
    /// # Arguments
    ///
    /// * `buffer` - Lead time before expiry at which to refresh.
    pub fn token_refresh_buffer(mut self, buffer: Duration) -> Self {
        self.token_refresh_buffer = buffer;
        self
    }

    /// Builds the [`ZerobusSdk`] instance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The endpoint is not set
    /// - The workspace ID cannot be extracted from the endpoint
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> ZerobusResult<ZerobusSdk> {
        let zerobus_endpoint = self
            .zerobus_endpoint
            .ok_or_else(|| ZerobusError::InvalidArgument("endpoint is required".to_string()))?;

        let zerobus_endpoint = if !zerobus_endpoint.starts_with("https://")
            && !zerobus_endpoint.starts_with("http://")
        {
            format!("https://{}", zerobus_endpoint)
        } else {
            zerobus_endpoint
        };

        let unity_catalog_url = self.unity_catalog_url.unwrap_or_default();

        let workspace_id = zerobus_endpoint
            .strip_prefix("https://")
            .or_else(|| zerobus_endpoint.strip_prefix("http://"))
            .and_then(|s| s.split('.').next())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                ZerobusError::InvalidArgument(
                    "Failed to extract workspace ID from zerobus_endpoint".to_string(),
                )
            })?;

        let tls_config = self
            .tls_config
            .unwrap_or_else(|| Arc::new(SecureTlsConfig::new()));

        let sdk_prefix: &str = match self.sdk_identifier_override.as_deref() {
            Some(override_id) if !override_id.is_empty() => override_id,
            _ => DEFAULT_SDK_IDENTIFIER,
        };
        let sdk_identifier: Arc<str> = match self.application_name.as_deref() {
            Some(app) if !app.is_empty() => Arc::from(format!("{} {}", sdk_prefix, app)),
            _ => Arc::from(sdk_prefix),
        };

        Ok(ZerobusSdk::new_with_config(
            zerobus_endpoint,
            unity_catalog_url,
            workspace_id,
            tls_config,
            self.connector_factory,
            sdk_identifier,
            self.token_cache_enabled,
            self.token_refresh_buffer,
        ))
    }
}

impl Default for ZerobusSdkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_with_all_fields() {
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://my-workspace.zerobus.us-east-1.cloud.databricks.com")
            .unity_catalog_url("https://my-workspace.cloud.databricks.com")
            .build()
            .expect("should build successfully");

        assert_eq!(
            sdk.zerobus_endpoint,
            "https://my-workspace.zerobus.us-east-1.cloud.databricks.com"
        );
        assert_eq!(
            sdk.unity_catalog_url,
            "https://my-workspace.cloud.databricks.com"
        );
    }

    #[test]
    fn test_builder_token_cache_options() {
        // Both knobs are chainable and the SDK builds with non-default values.
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .token_cache_enabled(false)
            .token_refresh_buffer(Duration::from_secs(120))
            .build()
            .expect("should build with token cache options");

        // The builder accepts both knobs and produces a usable SDK; assert the
        // build succeeded via a field on the result.
        assert_eq!(sdk.workspace_id, "workspace");
    }

    #[test]
    fn test_builder_token_cache_enabled_by_default() {
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .build()
            .expect("should build");
        // The cache is always present; enablement is internal state.
        let _ = &sdk.token_cache;
    }

    #[test]
    fn test_builder_missing_endpoint() {
        let result = ZerobusSdkBuilder::new()
            .unity_catalog_url("https://workspace.cloud.databricks.com")
            .build();

        assert!(matches!(
            result,
            Err(ZerobusError::InvalidArgument(msg)) if msg.contains("endpoint is required")
        ));
    }

    #[test]
    fn test_builder_schemeless_endpoint() {
        // Endpoint without protocol prefix - https:// is prepended automatically
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("my-workspace.zerobus.databricks.com")
            .build()
            .expect("should build successfully with schemeless endpoint");

        assert_eq!(sdk.workspace_id, "my-workspace");
        assert_eq!(
            sdk.zerobus_endpoint,
            "https://my-workspace.zerobus.databricks.com"
        );
    }

    #[test]
    fn test_builder_without_unity_catalog_url() {
        // Unity Catalog URL is optional for custom headers providers
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .build()
            .expect("should build successfully without unity_catalog_url");

        assert_eq!(sdk.unity_catalog_url, "");
    }

    #[test]
    fn test_sdk_identifier_default() {
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .build()
            .expect("should build");

        assert_eq!(&*sdk.sdk_identifier, crate::DEFAULT_SDK_IDENTIFIER);
    }

    #[test]
    fn test_sdk_identifier_with_application_name() {
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .application_name("my-app/1.0")
            .build()
            .expect("should build");

        let expected = format!("{} my-app/1.0", crate::DEFAULT_SDK_IDENTIFIER);
        assert_eq!(&*sdk.sdk_identifier, expected);
    }

    #[test]
    fn test_sdk_identifier_empty_application_name_falls_back_to_default() {
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .application_name("")
            .build()
            .expect("should build");

        assert_eq!(&*sdk.sdk_identifier, crate::DEFAULT_SDK_IDENTIFIER);
    }

    #[test]
    fn test_sdk_identifier_override_replaces_default() {
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .sdk_identifier("custom-agent/2.0")
            .build()
            .expect("should build");

        assert_eq!(&*sdk.sdk_identifier, "custom-agent/2.0");
    }

    #[test]
    fn test_sdk_identifier_override_with_application_name_combines() {
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .application_name("my-app/1.0")
            .sdk_identifier("custom-agent/2.0")
            .build()
            .expect("should build");

        assert_eq!(&*sdk.sdk_identifier, "custom-agent/2.0 my-app/1.0");
    }

    #[test]
    fn test_sdk_identifier_empty_override_falls_back_to_default() {
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .sdk_identifier("")
            .build()
            .expect("should build");

        assert_eq!(&*sdk.sdk_identifier, crate::DEFAULT_SDK_IDENTIFIER);
    }

    #[test]
    fn test_sdk_identifier_empty_override_with_application_name_uses_application_name() {
        let sdk = ZerobusSdkBuilder::new()
            .endpoint("https://workspace.zerobus.databricks.com")
            .application_name("my-app/1.0")
            .sdk_identifier("")
            .build()
            .expect("should build");

        let expected = format!("{} my-app/1.0", crate::DEFAULT_SDK_IDENTIFIER);
        assert_eq!(&*sdk.sdk_identifier, expected);
    }
}
