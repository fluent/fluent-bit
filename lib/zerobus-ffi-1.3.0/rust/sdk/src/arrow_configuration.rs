//! Configuration options for Arrow Flight streams.
//!
//! **Beta**: Arrow Flight ingestion is in Beta. The API is stabilising but may
//! still change before reaching GA.

use crate::stream_options::defaults;
use arrow_ipc::CompressionType;

/// Configuration options for Arrow Flight stream creation and operation.
///
/// These options control the behavior of Arrow Flight ingestion streams, including
/// backpressure limits, timeout settings, and recovery policies.
///
/// **Do not construct this directly.** Configure Arrow streams via the builder API:
///
/// ```rust,ignore
/// let stream = sdk
///     .stream_builder()
///     .table("catalog.schema.table")
///     .oauth("client-id", "client-secret")
///     .arrow(schema)
///     .max_inflight_batches(100)
///     .server_lack_of_ack_timeout_ms(30_000)
///     .recovery(true)
///     .build_arrow()
///     .await?;
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ArrowStreamConfigurationOptions {
    /// Maximum number of batches that can be in-flight (sent but not acknowledged).
    ///
    /// This limit controls memory usage and backpressure. When this limit is reached,
    /// `ingest_batch()` calls will block until acknowledgments free up space.
    ///
    /// Default: 1,000
    pub max_inflight_batches: usize,

    /// Whether to enable automatic stream recovery on failure.
    ///
    /// When enabled, the SDK will automatically attempt to reconnect and recover
    /// the stream when encountering retryable errors.
    ///
    /// Default: `true`
    pub recovery: bool,

    /// Timeout in milliseconds for each stream recovery attempt.
    ///
    /// If a recovery attempt takes longer than this, it will be retried.
    ///
    /// Default: 15,000 (15 seconds)
    pub recovery_timeout_ms: u64,

    /// Backoff time in milliseconds between stream recovery retry attempts.
    ///
    /// The SDK will wait this duration before attempting another recovery after a failure.
    ///
    /// Default: 2,000 (2 seconds)
    pub recovery_backoff_ms: u64,

    /// Maximum number of recovery retry attempts before giving up.
    ///
    /// After this many failed attempts, the stream will close and return an error.
    ///
    /// Default: 4
    pub recovery_retries: u32,

    /// Timeout in milliseconds for waiting for server acknowledgements.
    ///
    /// If no acknowledgement is received within this time (and there are pending batches),
    /// the stream will be considered failed and recovery will be triggered (if enabled).
    ///
    /// Default: 60,000 (60 seconds)
    pub server_lack_of_ack_timeout_ms: u64,

    /// Timeout in milliseconds for flush operations.
    ///
    /// If a `flush()` call cannot complete within this time, it will return a timeout error.
    ///
    /// Default: 300,000 (5 minutes)
    pub flush_timeout_ms: u64,

    /// Timeout in milliseconds for stream connection establishment.
    ///
    /// If the Arrow Flight stream cannot be established within this time,
    /// stream creation will fail.
    ///
    /// Default: 30,000 (30 seconds)
    pub connection_timeout_ms: u64,

    /// Optional Arrow IPC compression for Flight payloads.
    ///
    /// Supported compression types from `arrow_ipc::CompressionType`:
    /// - `CompressionType::LZ4_FRAME` - LZ4 frame compression
    /// - `CompressionType::ZSTD` - Zstandard compression
    ///
    /// Default: `None`
    pub ipc_compression: Option<CompressionType>,

    /// Maximum time in milliseconds to wait during graceful stream close.
    ///
    /// When the server sends a close stream signal indicating it will close the stream,
    /// the SDK enters a "paused" state where it:
    /// - Continues accepting and buffering new `ingest_batch()` calls
    /// - Stops sending buffered batches to the server
    /// - Continues processing acknowledgments for in-flight batches
    /// - Waits for either all in-flight batches to be acknowledged or the timeout to expire
    ///
    /// Configuration values:
    /// - `None`: Wait for the full server-specified duration (most graceful)
    /// - `Some(0)`: Immediate recovery, close stream right away
    /// - `Some(x)`: Wait up to min(x, server_duration) milliseconds
    ///
    /// Default: `None` (wait for full server duration)
    pub stream_paused_max_wait_time_ms: Option<u64>,
}

impl Default for ArrowStreamConfigurationOptions {
    fn default() -> Self {
        Self {
            max_inflight_batches: 1_000,
            recovery: defaults::RECOVERY,
            recovery_timeout_ms: defaults::RECOVERY_TIMEOUT_MS,
            recovery_backoff_ms: defaults::RECOVERY_BACKOFF_MS,
            recovery_retries: defaults::RECOVERY_RETRIES,
            server_lack_of_ack_timeout_ms: defaults::SERVER_LACK_OF_ACK_TIMEOUT_MS,
            flush_timeout_ms: defaults::FLUSH_TIMEOUT_MS,
            connection_timeout_ms: defaults::CONNECTION_TIMEOUT_MS,
            ipc_compression: None,
            stream_paused_max_wait_time_ms: None,
        }
    }
}
