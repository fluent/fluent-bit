use crate::default_token_factory::DefaultTokenFactory;
use crate::token_cache::{TokenCache, DEFAULT_REFRESH_BUFFER};
use crate::ZerobusResult;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

/// A trait for providing custom headers for gRPC requests.
///
/// This trait allows you to implement custom logic for generating authentication headers,
/// such as fetching tokens from different OAuth providers or using alternative
/// authentication mechanisms.
///
/// The HTTP `user-agent` header is set by the SDK on the underlying tonic
/// `Endpoint` and cannot be overridden by values returned from `get_headers`.
/// Use [`ZerobusSdkBuilder::application_name`](crate::ZerobusSdkBuilder::application_name)
/// to customize it.
///
/// # Examples
///
/// ```no_run
/// # use databricks_zerobus_ingest_sdk::{HeadersProvider, ZerobusResult};
/// # use std::collections::HashMap;
/// # use async_trait::async_trait;
///
/// struct MyCustomAuthProvider;
///
/// #[async_trait]
/// impl HeadersProvider for MyCustomAuthProvider {
///     async fn get_headers(&self) -> ZerobusResult<HashMap<&'static str, String>> {
///         let mut headers = HashMap::new();
///         headers.insert("some_key", "some_value".to_string());
///         Ok(headers)
///     }
/// }
/// ```
#[async_trait]
pub trait HeadersProvider: Send + Sync {
    /// Asynchronously gets the headers for a request.
    ///
    /// # Returns
    ///
    /// A `ZerobusResult` containing a `HashMap` of header names and values.
    ///
    /// # Errors
    ///
    /// Returns a `ZerobusError` if header generation fails (e.g., token request fails).
    async fn get_headers(&self) -> ZerobusResult<HashMap<&'static str, String>>;

    /// Invalidates any cached authentication state so the next `get_headers`
    /// call re-derives it from scratch.
    ///
    /// The SDK calls this when the server rejects the supplied credentials with
    /// an authentication error during stream creation. The default is a no-op,
    /// which is correct for providers that hold no cache; the built-in OAuth
    /// provider overrides it to drop its cached token so the next call re-mints.
    async fn invalidate(&self) {}
}

/// The default headers provider that uses OAuth 2.0 with Unity Catalog.
///
/// This provider implements the OAuth 2.0 client credentials flow to obtain
/// access tokens for authenticating with the Zerobus service.
pub struct OAuthHeadersProvider {
    client_id: String,
    client_secret: String,
    table_name: String,
    workspace_id: String,
    unity_catalog_url: String,
    token_cache: Arc<TokenCache>,
}

impl OAuthHeadersProvider {
    /// Creates a new `OAuthHeadersProvider`.
    ///
    /// This standalone constructor caches tokens for the lifetime of the
    /// returned provider only. When streams are created via
    /// [`ZerobusSdk::stream_builder`](crate::ZerobusSdk::stream_builder) the SDK
    /// supplies a shared cache so tokens are reused across streams; see
    /// [`with_cache`](Self::with_cache).
    pub fn new(
        client_id: String,
        client_secret: String,
        table_name: String,
        workspace_id: String,
        unity_catalog_url: String,
    ) -> Self {
        Self::with_cache(
            client_id,
            client_secret,
            table_name,
            workspace_id,
            unity_catalog_url,
            Arc::new(TokenCache::new(true, DEFAULT_REFRESH_BUFFER)),
        )
    }

    /// Creates a new `OAuthHeadersProvider` backed by a shared token cache.
    ///
    /// Used internally so all streams created from one `ZerobusSdk` reuse cached
    /// tokens rather than minting a fresh one per stream.
    pub(crate) fn with_cache(
        client_id: String,
        client_secret: String,
        table_name: String,
        workspace_id: String,
        unity_catalog_url: String,
        token_cache: Arc<TokenCache>,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            table_name,
            workspace_id,
            unity_catalog_url,
            token_cache,
        }
    }
}

#[async_trait]
impl HeadersProvider for OAuthHeadersProvider {
    async fn get_headers(&self) -> ZerobusResult<HashMap<&'static str, String>> {
        let token = self
            .token_cache
            .get_or_fetch(
                &self.client_id,
                &self.client_secret,
                &self.table_name,
                |reason| {
                    DefaultTokenFactory::fetch_token(
                        &self.unity_catalog_url,
                        &self.table_name,
                        &self.client_id,
                        &self.client_secret,
                        &self.workspace_id,
                        reason,
                    )
                },
            )
            .await?;
        let mut headers = HashMap::new();
        headers.insert("authorization", format!("Bearer {}", token));
        headers.insert("x-databricks-zerobus-table-name", self.table_name.clone());
        Ok(headers)
    }

    async fn invalidate(&self) {
        self.token_cache
            .invalidate(&self.client_id, &self.client_secret, &self.table_name)
            .await;
    }
}
