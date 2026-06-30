use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::{ZerobusError, ZerobusResult};

/// An access token together with its time-to-live as reported by the OAuth
/// server, if any.
pub(crate) struct FetchedToken {
    /// The OAuth 2.0 access token.
    pub(crate) token: String,
    /// Lifetime of the token derived from the `expires_in` field of the OAuth
    /// response. `None` if the server did not return a usable `expires_in`, in
    /// which case the token must not be cached.
    pub(crate) expires_in: Option<Duration>,
}

/// Why a token mint was triggered. Logged on the mint so operators can tell a
/// cold start from a proactive refresh from caching being off.
#[derive(Clone, Copy, Debug)]
pub(crate) enum MintReason {
    /// No usable cached token (cold start or the cached token had expired).
    ColdMiss,
    /// A cached token entered the refresh window and was proactively renewed.
    Refresh,
    /// Token caching is disabled, so every stream creation mints.
    CacheDisabled,
    /// Minted outside the cache via the public `get_token`.
    Direct,
}

impl MintReason {
    fn as_str(self) -> &'static str {
        match self {
            MintReason::ColdMiss => "cold_miss",
            MintReason::Refresh => "refresh",
            MintReason::CacheDisabled => "cache_disabled",
            MintReason::Direct => "direct",
        }
    }
}

/// Default OAuth 2.0 token factory for Unity Catalog authentication.
///
/// This factory implements the OAuth 2.0 client credentials flow with Unity Catalog
/// authorization details to obtain access tokens for Zerobus API access.
pub struct DefaultTokenFactory {}

impl DefaultTokenFactory {
    /// Obtains an OAuth 2.0 access token for Zerobus API access.
    ///
    /// # Arguments
    ///
    /// * `uc_endpoint` - Unity Catalog endpoint URL
    /// * `table_name` - Full table name in format "catalog.schema.table"
    /// * `client_id` - OAuth client ID
    /// * `client_secret` - OAuth client secret
    /// * `workspace_id` - Databricks workspace ID
    ///
    /// # Returns
    ///
    /// Returns an access token string on success, or a `ZerobusError` on failure.
    ///
    /// # Errors
    ///
    /// * `InvalidUCTokenError` - If the token request fails or returns invalid data
    pub async fn get_token(
        uc_endpoint: &str,
        table_name: &str,
        client_id: &str,
        client_secret: &str,
        workspace_id: &str,
    ) -> ZerobusResult<String> {
        Self::fetch_token(
            uc_endpoint,
            table_name,
            client_id,
            client_secret,
            workspace_id,
            MintReason::Direct,
        )
        .await
        .map(|fetched| fetched.token)
    }

    /// Obtains an OAuth 2.0 access token along with its reported lifetime.
    ///
    /// This is the caching-aware variant of [`get_token`](Self::get_token): in
    /// addition to the token it returns the `expires_in` value from the OAuth
    /// response so callers can cache the token until it nears expiry.
    pub(crate) async fn fetch_token(
        uc_endpoint: &str,
        table_name: &str,
        client_id: &str,
        client_secret: &str,
        workspace_id: &str,
        reason: MintReason,
    ) -> ZerobusResult<FetchedToken> {
        debug!(table = %table_name, "requesting UC OAuth token");
        let started = Instant::now();
        let result = Self::fetch_token_inner(
            uc_endpoint,
            table_name,
            client_id,
            client_secret,
            workspace_id,
        )
        .await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match &result {
            Ok(FetchedToken {
                expires_in: Some(ttl),
                ..
            }) => info!(
                table = %table_name,
                reason = reason.as_str(),
                expires_in_secs = ttl.as_secs(),
                elapsed_ms,
                "minted UC OAuth token"
            ),
            Ok(FetchedToken {
                expires_in: None, ..
            }) => warn!(
                table = %table_name,
                reason = reason.as_str(),
                elapsed_ms,
                "minted UC OAuth token but UC returned no expires_in; token will not be cached"
            ),
            Err(err) => warn!(
                table = %table_name,
                reason = reason.as_str(),
                retryable = err.is_retryable(),
                elapsed_ms,
                "failed to mint UC OAuth token: {err}"
            ),
        }
        result
    }

    async fn fetch_token_inner(
        uc_endpoint: &str,
        table_name: &str,
        client_id: &str,
        client_secret: &str,
        workspace_id: &str,
    ) -> ZerobusResult<FetchedToken> {
        let (catalog, schema, table) = Self::parse_table_name(table_name)?;

        let uc_endpoint = uc_endpoint.to_string();
        let databricks_client_id = client_id.to_string();
        let databricks_client_secret = client_secret.to_string();
        let workspace_id = workspace_id.to_string();

        let authorization_details = serde_json::json!([
            {
                "type": "unity_catalog_privileges",
                "privileges": ["USE CATALOG"],
                "object_type": "CATALOG",
                "object_full_path": catalog
            },
            {
                "type": "unity_catalog_privileges",
                "privileges": ["USE SCHEMA"],
                "object_type": "SCHEMA",
                "object_full_path": format!("{}.{}", catalog, schema)
            },
            {
                "type": "unity_catalog_privileges",
                "privileges": ["SELECT", "MODIFY"],
                "object_type": "TABLE",
                "object_full_path": format!("{}.{}.{}", catalog, schema, table),
                "operations": ["zerobuswrite"]
            }
        ]);

        let client = reqwest::Client::new();

        let params = [
            ("grant_type", "client_credentials".to_string()),
            ("scope", "all-apis".to_string()),
            (
                "resource",
                format!(
                    "api://databricks/workspaces/{}/zerobusDirectWriteApi",
                    workspace_id
                )
                .to_string(),
            ),
            ("authorization_details", authorization_details.to_string()),
        ];

        let token_endpoint = format!("{}/oidc/v1/token", uc_endpoint);
        let resp = client
            .post(&token_endpoint)
            .basic_auth(databricks_client_id, Some(databricks_client_secret))
            .form(&params)
            .send()
            .await
            .map_err(Self::handle_http_error)?;

        if !resp.status().is_success() {
            let status_code = resp.status().as_u16();
            let error_body = resp
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());

            return Err(Self::classify_status_code(status_code, error_body));
        }

        let body: serde_json::Value = resp.json().await.map_err(|e| {
            ZerobusError::InvalidUCTokenError(format!("Parse failed with error: {}", e))
        })?;

        let token = body["access_token"]
            .as_str()
            .ok_or_else(|| ZerobusError::InvalidUCTokenError("access_token missing".to_string()))?
            .to_string();

        // Reject a token that can't be a header value before it is returned, so
        // an unusable token never enters the cache and poisons it until expiry.
        if !Self::is_usable_as_header(&token) {
            return Err(ZerobusError::InvalidUCTokenError(
                "access token is not a valid HTTP header value".to_string(),
            ));
        }

        let expires_in = Self::parse_expires_in(&body);

        Ok(FetchedToken { token, expires_in })
    }

    /// Reports whether `token` can be sent as the `authorization` header value
    /// (`Bearer <token>`). The gRPC and Arrow paths both encode it this way, so a
    /// token that fails here is unusable and must not be cached.
    fn is_usable_as_header(token: &str) -> bool {
        tonic::metadata::AsciiMetadataValue::try_from(format!("Bearer {token}").as_str()).is_ok()
    }

    /// Parses the OAuth `expires_in` field (token lifetime in seconds) into a
    /// `Duration`. It is optional in the OAuth spec; if it is missing or not a
    /// positive integer the token has no known TTL and must not be cached.
    fn parse_expires_in(body: &serde_json::Value) -> Option<Duration> {
        body["expires_in"]
            .as_u64()
            .filter(|secs| *secs > 0)
            .map(Duration::from_secs)
    }

    /// Classifies HTTP status codes as retryable or non-retryable errors.
    ///
    /// # Arguments
    ///
    /// * `status_code` - HTTP status code (e.g., 404, 500)
    /// * `message` - Error message or response body
    ///
    /// # Returns
    ///
    /// * `TokenFetchError` for 5xx server errors (retryable)
    /// * `InvalidUCTokenError` for 4xx client errors (non-retryable)
    fn classify_status_code(status_code: u16, message: String) -> ZerobusError {
        if status_code >= 500 {
            ZerobusError::TokenFetchError(format!(
                "Unity catalog server error ({}): {}",
                status_code, message
            ))
        } else {
            ZerobusError::InvalidUCTokenError(format!(
                "Client error ({}): {}",
                status_code, message
            ))
        }
    }

    /// Helper to classify HTTP errors as retryable (TokenFetchError) or non-retryable.
    ///
    /// Retryable:
    /// - Network errors (timeout, connection failure)
    /// - Server errors (5xx status codes)
    ///
    /// Non-retryable:
    /// - Client errors (4xx status codes - bad credentials, invalid request, etc.)
    fn handle_http_error(error: reqwest::Error) -> ZerobusError {
        if error.is_timeout() || error.is_connect() {
            return ZerobusError::TokenFetchError(format!("Network error: {}", error));
        }
        if let Some(status) = error.status() {
            return Self::classify_status_code(status.as_u16(), error.to_string());
        }
        ZerobusError::InvalidUCTokenError(format!("Request failed: {}", error))
    }

    /// Parses a fully qualified table name into its components.
    ///
    /// # Arguments
    ///
    /// * `table_name` - Full table name in format "catalog.schema.table"
    ///
    /// # Returns
    ///
    /// Returns a tuple of (catalog, schema, table) on success.
    ///
    /// # Errors
    ///
    /// * `InvalidTableName` - If the table name doesn't have exactly 3 non-empty parts.
    #[allow(clippy::result_large_err)]
    fn parse_table_name(table_name: &str) -> Result<(String, String, String), ZerobusError> {
        let parts: Vec<&str> = table_name.split('.').collect();

        if parts.len() != 3 {
            return Err(ZerobusError::InvalidTableName(format!(
                "Table name must have exactly 3 parts (catalog.schema.table), found {} parts",
                parts.len()
            )));
        }

        let catalog = parts[0];
        let schema = parts[1];
        let table = parts[2];

        if catalog.is_empty() {
            return Err(ZerobusError::InvalidTableName(
                "Catalog name cannot be empty".to_string(),
            ));
        }
        if schema.is_empty() {
            return Err(ZerobusError::InvalidTableName(
                "Schema name cannot be empty".to_string(),
            ));
        }
        if table.is_empty() {
            return Err(ZerobusError::InvalidTableName(
                "Table name cannot be empty".to_string(),
            ));
        }

        Ok((catalog.to_string(), schema.to_string(), table.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_table_name_valid() {
        let result = DefaultTokenFactory::parse_table_name("catalog_1.schema_2.table_3");
        assert!(result.is_ok());
        let (catalog, schema, table) = result.unwrap();
        assert_eq!(catalog, "catalog_1");
        assert_eq!(schema, "schema_2");
        assert_eq!(table, "table_3");
    }

    #[test]
    fn test_parse_expires_in() {
        let with_ttl = serde_json::json!({ "expires_in": 3600 });
        assert_eq!(
            DefaultTokenFactory::parse_expires_in(&with_ttl),
            Some(Duration::from_secs(3600))
        );

        let missing = serde_json::json!({ "access_token": "abc" });
        assert_eq!(DefaultTokenFactory::parse_expires_in(&missing), None);

        let zero = serde_json::json!({ "expires_in": 0 });
        assert_eq!(DefaultTokenFactory::parse_expires_in(&zero), None);

        // A string value (non-integer) is not usable and yields no TTL.
        let non_numeric = serde_json::json!({ "expires_in": "3600" });
        assert_eq!(DefaultTokenFactory::parse_expires_in(&non_numeric), None);
    }

    #[test]
    fn test_is_usable_as_header() {
        // A normal JWT-shaped token is a valid header value.
        assert!(DefaultTokenFactory::is_usable_as_header(
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig-_value"
        ));
        // Control characters (e.g. an embedded newline) make it unusable.
        assert!(!DefaultTokenFactory::is_usable_as_header("bad\ntoken"));
        assert!(!DefaultTokenFactory::is_usable_as_header("bad\0token"));
    }

    #[test]
    fn test_parse_table_name_invalid() {
        let invalid_cases = vec![
            ("catalog.schema.table.extra", "exactly 3 parts"),
            ("catalog.schema.table.with.dots", "exactly 3 parts"),
            ("catalog", "exactly 3 parts"),
            ("catalog.schema", "exactly 3 parts"),
            ("", "exactly 3 parts"),
            (".schema.table", "Catalog name cannot be empty"),
            ("catalog..table", "Schema name cannot be empty"),
            ("catalog.schema.", "Table name cannot be empty"),
            ("..", "Catalog name cannot be empty"),
            ("..table", "Catalog name cannot be empty"),
            ("catalog..", "Schema name cannot be empty"),
        ];

        for (input, expected_error) in invalid_cases {
            let result = DefaultTokenFactory::parse_table_name(input);
            assert!(
                result.is_err(),
                "Expected '{}' to be invalid, but it was parsed successfully",
                input
            );
            match result {
                Err(ZerobusError::InvalidTableName(msg)) => {
                    assert!(
                        msg.contains(expected_error),
                        "For input '{}', expected error to contain '{}', but got: '{}'",
                        input,
                        expected_error,
                        msg
                    );
                }
                _ => panic!("Expected InvalidTableName error for '{}'", input),
            }
        }
    }
}
