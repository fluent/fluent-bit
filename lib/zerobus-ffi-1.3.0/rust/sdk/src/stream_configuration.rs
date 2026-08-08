use std::sync::Arc;

use crate::callbacks::AckCallback;
use crate::databricks::zerobus::RecordType;
use crate::stream_options::defaults;

/// Configuration options for stream creation, recovery of broken streams and flushing.
///
/// These options control the behavior of ingestion streams, including memory limits,
/// recovery policies, and timeout settings.
///
/// **Do not construct this directly.** Configure streams via the builder API:
///
/// ```rust,ignore
/// let stream = sdk
///     .stream_builder()
///     .table("catalog.schema.table")
///     .oauth("client-id", "client-secret")
///     .json()
///     .max_inflight_requests(1_000_000)
///     .recovery(true)
///     .recovery_timeout_ms(20_000)
///     .recovery_retries(5)
///     .build()
///     .await?;
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct StreamConfigurationOptions {
    /// Maximum number of requests that can be sending or pending acknowledgement at any given time.
    ///
    /// This limit controls memory usage and backpressure. When this limit is reached,
    /// `ingest_record()` and `ingest_records()` calls will block until acknowledgments free up space.
    ///
    /// Default: 1,000,000
    pub max_inflight_requests: usize,

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
    /// If no acknowledgement is received within this time (and there are pending records),
    /// the stream will be considered failed and recovery will be triggered.
    ///
    /// Default: 60,000 (60 seconds)
    pub server_lack_of_ack_timeout_ms: u64,

    /// Timeout in milliseconds for flush operations.
    ///
    /// If a flush() call cannot complete within this time, it will return a timeout error.
    ///
    /// Default: 300,000 (5 minutes)
    pub flush_timeout_ms: u64,

    /// Type of record to ingest.
    ///
    /// Supported values:
    /// - RecordType::Proto
    /// - RecordType::Json
    /// - RecordType::Unspecified
    ///
    /// Default: RecordType::Proto
    pub record_type: RecordType,

    /// Maximum time in milliseconds to wait during graceful stream close.
    ///
    /// When the server sends a CloseStreamSignal indicating it will close the stream,
    /// the SDK can enter a "paused" state where it:
    /// - Continues accepting and buffering new ingest_record() calls
    /// - Stops sending buffered records to the server
    /// - Continues processing acknowledgments for in-flight records
    /// - Waits for either all in-flight records to be acknowledged or the timeout to expire
    ///
    /// Configuration values:
    /// - `None`: Wait for the full server-specified duration (most graceful)
    /// - `Some(0)`: Immediate recovery, close stream right away (current behavior)
    /// - `Some(x)`: Wait up to min(x, server_duration) milliseconds
    ///
    /// Default: `None` (wait for full server duration)
    pub stream_paused_max_wait_time_ms: Option<u64>,

    /// Optional callback invoked when records are acknowledged or encounter errors.
    ///
    /// When set, this callback will be invoked:
    /// - On successful acknowledgment: `on_ack(offset_id)` is called
    /// - On error: `on_error(offset_id, error_message)` is called
    ///
    ///
    /// Default: `None` (no callbacks)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use std::sync::Arc;
    /// use databricks_zerobus_ingest_sdk::{AckCallback, OffsetId};
    ///
    /// struct MyCallback;
    ///
    /// impl AckCallback for MyCallback {
    ///     fn on_ack(&self, offset_id: OffsetId) {
    ///         println!("Acknowledged: {}", offset_id);
    ///     }
    ///
    ///     fn on_error(&self, offset_id: OffsetId, error_message: &str) {
    ///         eprintln!("Error {}: {}", offset_id, error_message);
    ///     }
    /// }
    ///
    /// let stream = sdk
    ///     .stream_builder()
    ///     .table("catalog.schema.table")
    ///     .oauth("client-id", "client-secret")
    ///     .json()
    ///     .ack_callback(Arc::new(MyCallback))
    ///     .build()
    ///     .await?;
    /// ```
    pub ack_callback: Option<Arc<dyn AckCallback>>,

    /// Maximum time in milliseconds to wait for callbacks to finish after calling close() on the stream.
    ///
    /// When the stream is closed, all tasks are shut down and the callback handler task is
    /// given a timeout to finish processing callbacks. After the timeout expires, or once all
    /// callbacks have been processed, the callback handler task is aborted and the stream is
    /// fully closed.
    ///
    /// Configuration values:
    /// - `None`: Wait forever
    /// - `Some(x)`: Wait up to x milliseconds
    ///
    /// Default: `Some(5000)` (wait 5 seconds)
    pub callback_max_wait_time_ms: Option<u64>,
}

impl Default for StreamConfigurationOptions {
    fn default() -> Self {
        Self {
            max_inflight_requests: 1_000_000,
            recovery: defaults::RECOVERY,
            recovery_timeout_ms: defaults::RECOVERY_TIMEOUT_MS,
            recovery_backoff_ms: defaults::RECOVERY_BACKOFF_MS,
            recovery_retries: defaults::RECOVERY_RETRIES,
            server_lack_of_ack_timeout_ms: defaults::SERVER_LACK_OF_ACK_TIMEOUT_MS,
            flush_timeout_ms: defaults::FLUSH_TIMEOUT_MS,
            record_type: RecordType::Proto,
            stream_paused_max_wait_time_ms: None,
            ack_callback: None,
            callback_max_wait_time_ms: Some(defaults::CALLBACK_MAX_WAIT_TIME_MS),
        }
    }
}
