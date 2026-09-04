//! Callback system for acknowledgment notifications.
//!
//! This module provides a callback interface for receiving notifications when
//! records or batches are acknowledged by the server.
//!
//! # Examples
//!
//! ```
//! use databricks_zerobus_ingest_sdk::{AckCallback, OffsetId};
//!
//! struct MyCallback;
//!
//! impl AckCallback for MyCallback {
//!     fn on_ack(&self, offset_id: OffsetId) {
//!         println!("Acknowledged offset: {}", offset_id);
//!     }
//!
//!     fn on_error(&self, offset_id: OffsetId, error_message: &str) {
//!         eprintln!("Error for offset {}: {}", offset_id, error_message);
//!     }
//! }
//! ```

use crate::offset_generator::OffsetId;

/// Callback trait for receiving acknowledgment notifications.
///
/// Implement this trait to receive callbacks when records/batches are acknowledged
/// by the server or when errors occur.
///
/// # Thread Safety and Performance
///
/// Implementations must be `Send + Sync` as callbacks are invoked from
/// a dedicated background callback handler task.
///
/// **Important**: Callbacks are executed synchronously in a separate callback handler task.
/// Keep implementations lightweight (simple logging, metrics increment, etc.) to avoid
/// accumulating callback backlog. For heavy work like database writes, network calls,
/// or complex processing, consider using channels to send data to dedicated worker tasks.
///
/// # Examples
///
/// ```
/// use databricks_zerobus_ingest_sdk::{AckCallback, OffsetId};
/// use std::sync::atomic::{AtomicI64, Ordering};
///
/// struct CountingCallback {
///     ack_count: AtomicI64,
/// }
///
/// impl AckCallback for CountingCallback {
///     fn on_ack(&self, offset_id: OffsetId) {
///         self.ack_count.fetch_add(1, Ordering::Relaxed);
///     }
///
///     fn on_error(&self, offset_id: OffsetId, error_message: &str) {
///         eprintln!("Error: {}", error_message);
///     }
/// }
/// ```
pub trait AckCallback: Send + Sync {
    /// Called when a record/batch is successfully acknowledged by the server.
    ///
    /// **Note**: This runs synchronously in a dedicated callback handler task.
    /// Keep it lightweight (e.g., logging, metrics) to avoid callback backlog.
    ///
    /// # Parameters
    ///
    /// * `offset_id` - The logical offset ID that was acknowledged
    fn on_ack(&self, offset_id: OffsetId);

    /// Called when an error occurs for a specific record/batch.
    ///
    /// **Note**: This runs synchronously in a dedicated callback handler task.
    /// Keep it reasonably lightweight (e.g., logging, metrics) to avoid callback backlog.
    ///
    /// # Parameters
    ///
    /// * `offset_id` - The logical offset ID that encountered an error
    /// * `error_message` - Human-readable error description
    fn on_error(&self, offset_id: OffsetId, error_message: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

    struct TestCallback {
        last_ack: AtomicI64,
        error_called: AtomicBool,
    }

    impl AckCallback for TestCallback {
        fn on_ack(&self, offset_id: OffsetId) {
            self.last_ack.store(offset_id, Ordering::Relaxed);
        }

        fn on_error(&self, _offset_id: OffsetId, _error_message: &str) {
            self.error_called.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_callback_trait() {
        let callback = TestCallback {
            last_ack: AtomicI64::new(0),
            error_called: AtomicBool::new(false),
        };

        callback.on_ack(42);
        assert_eq!(callback.last_ack.load(Ordering::Relaxed), 42);

        callback.on_error(43, "test error");
        assert!(callback.error_called.load(Ordering::Relaxed));
    }
}
