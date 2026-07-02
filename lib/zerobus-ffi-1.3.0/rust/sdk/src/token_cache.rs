//! Per-table OAuth token cache for the default OAuth authentication path.
//!
//! Unity Catalog sets each token's lifetime (currently one hour), while a single
//! stream lives at most ~15 minutes. Without caching, every stream creation (and
//! every recovery) mints a fresh token, putting the Unity Catalog token endpoint
//! under unnecessary load when a client churns through many streams. The cache
//! does not assume a fixed lifetime — it serves a token until it nears the
//! `expires_in` the server reported.
//!
//! [`TokenCache`] caches one token per `(client_id, secret, table_name)` key on
//! the [`ZerobusSdk`](crate::ZerobusSdk) instance and serves it until it nears
//! expiry, refreshing lazily on access. Tokens are downscoped to a single table
//! (the authorization details embed the catalog/schema/table), so the table
//! name is part of the cache key.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::default_token_factory::{FetchedToken, MintReason};
use crate::ZerobusResult;

/// Default lead time before expiry at which a cached token is refreshed.
pub(crate) const DEFAULT_REFRESH_BUFFER: Duration = Duration::from_secs(300);

/// A cached token and the instant at which it expires.
struct CachedToken {
    value: String,
    expires_at: Instant,
}

impl CachedToken {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Identifies a cache entry. The client secret is keyed by its SHA-256 digest,
/// not plaintext: the digest is collision-resistant (distinct secrets cannot in
/// practice share a token) and keeps the raw secret out of the cache map. A
/// rotated secret yields a different digest, hence a fresh entry.
#[derive(Clone, PartialEq, Eq, Hash)]
struct TokenKey {
    client_id: String,
    secret_digest: [u8; 32],
    table_name: String,
}

impl TokenKey {
    fn new(client_id: &str, client_secret: &str, table_name: &str) -> Self {
        let secret_digest = Sha256::digest(client_secret.as_bytes()).into();
        Self {
            client_id: client_id.to_string(),
            secret_digest,
            table_name: table_name.to_string(),
        }
    }
}

/// Per-entry slot. Each key has its own mutex so that a cold-cache burst of
/// concurrent stream creations for the same table mints a single token
/// (single-flight) while creations for different tables never block each other.
type Slot = Arc<Mutex<Option<CachedToken>>>;

/// Caches OAuth tokens per table for the lifetime of a [`ZerobusSdk`].
///
/// Safe for concurrent use across streams created from the same SDK instance.
pub(crate) struct TokenCache {
    entries: Mutex<HashMap<TokenKey, Slot>>,
    refresh_buffer: Duration,
    enabled: bool,
}

impl TokenCache {
    pub(crate) fn new(enabled: bool, refresh_buffer: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            refresh_buffer,
            enabled,
        }
    }

    /// Returns a valid token for the given credentials and table, fetching a new
    /// one only if the cache is empty, the token has entered the refresh window,
    /// or caching is disabled.
    ///
    /// `fetch` is invoked to mint a fresh token. It is only ever called once per
    /// key at a time thanks to the per-entry lock.
    pub(crate) async fn get_or_fetch<F, Fut>(
        &self,
        client_id: &str,
        client_secret: &str,
        table_name: &str,
        fetch: F,
    ) -> ZerobusResult<String>
    where
        F: FnOnce(MintReason) -> Fut,
        Fut: std::future::Future<Output = ZerobusResult<FetchedToken>>,
    {
        if !self.enabled {
            return fetch(MintReason::CacheDisabled)
                .await
                .map(|fetched| fetched.token);
        }

        let key = TokenKey::new(client_id, client_secret, table_name);

        let slot = {
            let mut entries = self.entries.lock().await;
            // Sweep only on a miss, keeping the cost off the hot lookup path.
            if !entries.contains_key(&key) {
                Self::prune_expired(&mut entries);
            }
            Arc::clone(entries.entry(key).or_default())
        };

        // Hold the per-entry lock across the fetch so concurrent callers for the
        // same key reuse a single mint instead of stampeding the token endpoint.
        let mut guard = slot.lock().await;

        if let Some(cached) = guard.as_ref() {
            if !self.needs_refresh(cached) {
                debug!(table = %table_name, "token cache hit, reusing cached token");
                return Ok(cached.value.clone());
            }
        }

        // A present-but-stale token means we are refreshing; an empty slot is a
        // cold miss. The reason is surfaced on the mint log.
        let reason = if guard.is_some() {
            MintReason::Refresh
        } else {
            MintReason::ColdMiss
        };

        let fetched = match fetch(reason).await {
            Ok(fetched) => fetched,
            Err(err) => {
                // On a retryable failure, serve the still-valid cached token;
                // let non-retryable errors (bad/revoked creds) surface.
                if err.is_retryable() {
                    if let Some(cached) = guard.as_ref() {
                        if !cached.is_expired() {
                            warn!(table = %table_name, "token refresh failed (retryable); serving still-valid cached token");
                            return Ok(cached.value.clone());
                        }
                    }
                }
                return Err(err);
            }
        };

        let token = fetched.token.clone();

        // Cache only tokens with a usable TTL. `checked_add` also drops an absurd
        // `expires_in` that would overflow the clock instead of panicking.
        let expires_at = fetched
            .expires_in
            .and_then(|ttl| Instant::now().checked_add(ttl));
        match expires_at {
            Some(expires_at) => {
                *guard = Some(CachedToken {
                    value: fetched.token,
                    expires_at,
                });
            }
            None => {
                // No usable TTL: keep an existing still-valid token rather than
                // discarding it.
                let keep_existing = guard.as_ref().is_some_and(|cached| !cached.is_expired());
                if !keep_existing {
                    *guard = None;
                }
            }
        }

        Ok(token)
    }

    /// Drops any cached token for the given credentials and table so the next
    /// `get_or_fetch` re-mints. Called when the server rejects the token (e.g.
    /// it was revoked at the IdP), so the re-mint re-checks grants at UC. No-op
    /// when caching is disabled or no entry exists.
    pub(crate) async fn invalidate(&self, client_id: &str, client_secret: &str, table_name: &str) {
        if !self.enabled {
            return;
        }
        let key = TokenKey::new(client_id, client_secret, table_name);
        if self.entries.lock().await.remove(&key).is_some() {
            debug!(table = %table_name, "token cache entry invalidated after auth rejection");
        }
    }

    fn needs_refresh(&self, cached: &CachedToken) -> bool {
        // `checked_add` avoids a panic on an absurd refresh buffer (e.g.
        // `Duration::MAX`); an overflowing deadline means "always refresh".
        match Instant::now().checked_add(self.refresh_buffer) {
            Some(deadline) => deadline >= cached.expires_at,
            None => true,
        }
    }

    /// Drops entries whose token has fully expired. Locked (in-flight) entries,
    /// still-valid tokens, and empty slots are kept — keeping empty slots is
    /// what preserves single-flight for a key being minted concurrently.
    fn prune_expired(entries: &mut HashMap<TokenKey, Slot>) {
        entries.retain(|_, slot| match slot.try_lock() {
            Ok(guard) => match guard.as_ref() {
                Some(cached) => !cached.is_expired(),
                None => true,
            },
            Err(_) => true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fetched(token: &str, ttl_secs: Option<u64>) -> FetchedToken {
        FetchedToken {
            token: token.to_string(),
            expires_in: ttl_secs.map(Duration::from_secs),
        }
    }

    #[tokio::test]
    async fn caches_token_across_calls() {
        let cache = TokenCache::new(true, Duration::from_secs(60));
        let calls = AtomicUsize::new(0);

        let make = |_reason| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(fetched("tok", Some(3600)))
        };

        let a = cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();
        let b = cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();

        assert_eq!(a, "tok");
        assert_eq!(b, "tok");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second call should hit cache"
        );
    }

    #[tokio::test]
    async fn refetches_when_within_refresh_buffer() {
        // TTL (1s) is smaller than the refresh buffer (60s), so the token is
        // always considered due for refresh and every call mints anew.
        let cache = TokenCache::new(true, Duration::from_secs(60));
        let calls = AtomicUsize::new(0);

        let make = |_reason| async {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Ok(fetched(&format!("tok{n}"), Some(1)))
        };

        let a = cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();
        let b = cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();

        assert_eq!(a, "tok0");
        assert_eq!(b, "tok1");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn separate_tables_get_separate_entries() {
        let cache = TokenCache::new(true, Duration::from_secs(60));
        let calls = AtomicUsize::new(0);

        let make = |_reason| async {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Ok(fetched(&format!("tok{n}"), Some(3600)))
        };

        let a = cache
            .get_or_fetch("id", "secret", "c.s.t1", make)
            .await
            .unwrap();
        let b = cache
            .get_or_fetch("id", "secret", "c.s.t2", make)
            .await
            .unwrap();

        assert_ne!(a, b);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn rotated_secret_gets_new_entry() {
        let cache = TokenCache::new(true, Duration::from_secs(60));
        let calls = AtomicUsize::new(0);

        let make = |_reason| async {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Ok(fetched(&format!("tok{n}"), Some(3600)))
        };

        cache
            .get_or_fetch("id", "secret-v1", "c.s.t", make)
            .await
            .unwrap();
        cache
            .get_or_fetch("id", "secret-v2", "c.s.t", make)
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn token_without_ttl_is_not_cached() {
        let cache = TokenCache::new(true, Duration::from_secs(60));
        let calls = AtomicUsize::new(0);

        let make = |_reason| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(fetched("tok", None))
        };

        cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();
        cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2, "no TTL means no caching");
    }

    #[tokio::test]
    async fn invalidate_forces_remint_on_next_call() {
        let cache = TokenCache::new(true, Duration::from_secs(60));
        let calls = AtomicUsize::new(0);

        let make = |_reason| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(fetched("tok", Some(3600)))
        };

        cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();
        // Without invalidation a second call would hit the cache; invalidating
        // the entry forces the next call to re-mint.
        cache.invalidate("id", "secret", "c.s.t").await;
        cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn disabled_cache_always_fetches() {
        let cache = TokenCache::new(false, Duration::from_secs(60));
        let calls = AtomicUsize::new(0);

        let make = |_reason| async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(fetched("tok", Some(3600)))
        };

        cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();
        cache
            .get_or_fetch("id", "secret", "c.s.t", make)
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fetch_error_leaves_no_cached_entry() {
        let cache = TokenCache::new(true, Duration::from_secs(60));

        let err = cache
            .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                Err(crate::ZerobusError::TokenFetchError("boom".to_string()))
            })
            .await;
        assert!(err.is_err());

        // A subsequent successful fetch should still succeed and cache.
        let ok = cache
            .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                Ok(fetched("tok", Some(3600)))
            })
            .await
            .unwrap();
        assert_eq!(ok, "tok");
    }

    #[tokio::test]
    async fn refresh_failure_serves_still_valid_token() {
        let cache = TokenCache::new(true, Duration::from_secs(60));

        // Seed a token that is within the refresh buffer (ttl < buffer) but not
        // yet expired, so the next call is due for a refresh.
        let seeded = cache
            .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                Ok(fetched("valid", Some(30)))
            })
            .await
            .unwrap();
        assert_eq!(seeded, "valid");

        // The refresh mint fails; the still-valid cached token is served instead
        // of surfacing the error.
        let served = cache
            .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                Err(crate::ZerobusError::TokenFetchError("blip".to_string()))
            })
            .await
            .unwrap();
        assert_eq!(served, "valid");
    }

    #[tokio::test]
    async fn refresh_failure_propagates_non_retryable_error() {
        let cache = TokenCache::new(true, Duration::from_secs(60));

        // Seed a token that is within the refresh buffer but not yet expired.
        cache
            .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                Ok(fetched("valid", Some(30)))
            })
            .await
            .unwrap();

        // A non-retryable refresh error (e.g. revoked or invalid credentials)
        // must surface rather than being masked by the still-valid cached token.
        let result = cache
            .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                Err(crate::ZerobusError::InvalidUCTokenError(
                    "revoked".to_string(),
                ))
            })
            .await;
        assert!(matches!(
            result,
            Err(crate::ZerobusError::InvalidUCTokenError(_))
        ));
    }

    #[tokio::test]
    async fn no_ttl_response_does_not_evict_valid_token() {
        let cache = TokenCache::new(true, Duration::from_secs(60));

        // Seed a still-valid (within-buffer) token.
        cache
            .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                Ok(fetched("valid", Some(30)))
            })
            .await
            .unwrap();

        // A refresh returns a token with no TTL: the caller gets the fresh token,
        // but the cached valid token must not be discarded.
        let fresh = cache
            .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                Ok(fetched("nottl", None))
            })
            .await
            .unwrap();
        assert_eq!(fresh, "nottl");

        // A later refresh failure still finds the original valid token, proving
        // it was retained.
        let served = cache
            .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                Err(crate::ZerobusError::TokenFetchError("blip".to_string()))
            })
            .await
            .unwrap();
        assert_eq!(served, "valid");
    }

    #[tokio::test]
    async fn single_flight_mints_once_for_concurrent_callers() {
        let cache = Arc::new(TokenCache::new(true, Duration::from_secs(60)));
        let calls = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let calls = Arc::clone(&calls);
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_fetch("id", "secret", "c.s.t", |_reason| async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        // Hold the slot briefly so the other callers pile up
                        // behind the single-flight lock rather than racing.
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok(fetched("tok", Some(3600)))
                    })
                    .await
                    .unwrap()
            }));
        }

        for handle in handles {
            assert_eq!(handle.await.unwrap(), "tok");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "single-flight must mint exactly once for concurrent same-key callers"
        );
    }
}
