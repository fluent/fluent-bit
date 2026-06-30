// Allow clippy warnings for FFI code where unsafe operations are unavoidable
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::type_complexity)]

use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tokio::runtime::Runtime;
use tracing_subscriber::{fmt, EnvFilter};
extern crate libc;

use arrow_ipc::{reader::StreamReader, writer::StreamWriter, CompressionType};
use async_trait::async_trait;
use bytes::Bytes;
use databricks_zerobus_ingest_sdk::databricks::zerobus::RecordType;
use databricks_zerobus_ingest_sdk::schema::{descriptor_from_uc_schema, UcTableSchema};
use databricks_zerobus_ingest_sdk::{
    EncodedRecord, HeadersProvider, NoTlsConfig, ZerobusError, ZerobusResult, ZerobusSdk,
    ZerobusSdkBuilder, ZerobusStream,
};
use databricks_zerobus_ingest_sdk::{RecordBatch, StreamBuilder, ZerobusArrowStream};
use prost::Message;
use prost_reflect::{
    Cardinality, DescriptorPool, DeserializeOptions, DynamicMessage, MessageDescriptor,
};
use std::sync::Arc;

// Test module
#[cfg(test)]
mod tests;

// ============================================================================
// Arrow Flight FFI
// ============================================================================

/// Opaque handle for an Arrow Flight stream.
#[repr(C)]
pub struct CArrowStream {
    _private: [u8; 0],
}

/// Configuration options for Arrow Flight streams.
///
/// `ipc_compression`: -1 = None, 0 = LZ4_FRAME, 1 = ZSTD
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CArrowStreamConfigurationOptions {
    pub max_inflight_batches: usize,
    pub recovery: bool,
    pub recovery_timeout_ms: u64,
    pub recovery_backoff_ms: u64,
    pub recovery_retries: u32,
    pub server_lack_of_ack_timeout_ms: u64,
    pub flush_timeout_ms: u64,
    pub connection_timeout_ms: u64,
    /// -1 = None, 0 = LZ4_FRAME, 1 = ZSTD
    pub ipc_compression: i32,
    /// Maximum time in milliseconds to wait during graceful stream close.
    /// -1 = None (wait full server duration), 0 = immediate recovery, >0 = wait up to min(this, server_duration).
    pub stream_paused_max_wait_time_ms: i64,
}

fn c_to_compression(value: i32) -> Option<CompressionType> {
    match value {
        0 => Some(CompressionType::LZ4_FRAME),
        1 => Some(CompressionType::ZSTD),
        _ => None,
    }
}

fn c_to_stream_paused_ms(value: i64) -> Option<u64> {
    if value < 0 {
        None
    } else {
        Some(value as u64)
    }
}

/// An array of Arrow IPC-encoded batches, returned by `zerobus_arrow_stream_get_unacked_batches`.
/// Must be freed with `zerobus_arrow_free_batch_array`.
#[repr(C)]
pub struct CArrowBatchArray {
    /// Array of pointers to IPC-encoded batch bytes.
    pub batches: *mut *mut u8,
    /// Array of byte lengths, one per batch.
    pub lengths: *mut usize,
    /// Number of batches.
    pub count: usize,
}

// ---- Arrow pointer validation helpers ----

fn validate_arrow_stream_ptr<'a>(
    stream: *mut CArrowStream,
) -> Result<&'a ZerobusArrowStream, &'static str> {
    if stream.is_null() {
        return Err("Arrow stream pointer is null");
    }
    unsafe { Ok(&*(stream as *const ZerobusArrowStream)) }
}

fn validate_arrow_stream_ptr_mut<'a>(
    stream: *mut CArrowStream,
) -> Result<&'a mut ZerobusArrowStream, &'static str> {
    if stream.is_null() {
        return Err("Arrow stream pointer is null");
    }
    unsafe { Ok(&mut *(stream as *mut ZerobusArrowStream)) }
}

// ---- Arrow IPC helpers ----

/// Deserializes an `Arc<ArrowSchema>` from Arrow IPC stream bytes (schema-only stream).
#[allow(clippy::result_large_err)]
fn ipc_bytes_to_schema(
    bytes: &[u8],
) -> ZerobusResult<std::sync::Arc<databricks_zerobus_ingest_sdk::ArrowSchema>> {
    use std::io::Cursor;
    let cursor = Cursor::new(bytes);
    let reader = StreamReader::try_new(cursor, None).map_err(|e| {
        ZerobusError::InvalidArgument(format!("Failed to parse Arrow IPC schema: {e}"))
    })?;
    Ok(reader.schema().clone())
}

/// Serializes a `RecordBatch` to Arrow IPC stream bytes (schema + one batch).
#[allow(clippy::result_large_err)]
fn record_batch_to_ipc_bytes(batch: &RecordBatch) -> ZerobusResult<Vec<u8>> {
    let mut buf = Vec::new();
    let mut writer = StreamWriter::try_new(&mut buf, batch.schema().as_ref()).map_err(|e| {
        ZerobusError::InvalidArgument(format!("Failed to create Arrow IPC writer: {e}"))
    })?;
    writer.write(batch).map_err(|e| {
        ZerobusError::InvalidArgument(format!("Failed to write Arrow IPC batch: {e}"))
    })?;
    writer.finish().map_err(|e| {
        ZerobusError::InvalidArgument(format!("Failed to finish Arrow IPC stream: {e}"))
    })?;
    Ok(buf)
}

// Builder option application helpers

fn apply_c_stream_options<'a>(
    builder: StreamBuilder<'a>,
    c: &CStreamConfigurationOptions,
) -> StreamBuilder<'a> {
    builder
        .max_inflight_requests(c.max_inflight_requests)
        .recovery(c.recovery)
        .recovery_timeout_ms(c.recovery_timeout_ms)
        .recovery_backoff_ms(c.recovery_backoff_ms)
        .recovery_retries(c.recovery_retries)
        .server_lack_of_ack_timeout_ms(c.server_lack_of_ack_timeout_ms)
        .flush_timeout_ms(c.flush_timeout_ms)
        .stream_paused_max_wait_time_ms(if c.has_stream_paused_max_wait_time_ms {
            Some(c.stream_paused_max_wait_time_ms)
        } else {
            None
        })
        .callback_max_wait_time_ms(if c.has_callback_max_wait_time_ms {
            Some(c.callback_max_wait_time_ms)
        } else {
            None
        })
}

fn c_record_type(value: i32) -> RecordType {
    match value {
        1 => RecordType::Proto,
        2 => RecordType::Json,
        _ => RecordType::Unspecified,
    }
}

fn apply_c_arrow_stream_options<'a>(
    builder: StreamBuilder<'a>,
    c: &CArrowStreamConfigurationOptions,
) -> StreamBuilder<'a> {
    builder
        .max_inflight_batches(c.max_inflight_batches)
        .recovery(c.recovery)
        .recovery_timeout_ms(c.recovery_timeout_ms)
        .recovery_backoff_ms(c.recovery_backoff_ms)
        .recovery_retries(c.recovery_retries)
        .server_lack_of_ack_timeout_ms(c.server_lack_of_ack_timeout_ms)
        .flush_timeout_ms(c.flush_timeout_ms)
        .connection_timeout_ms(c.connection_timeout_ms)
        .ipc_compression(c_to_compression(c.ipc_compression))
        .stream_paused_max_wait_time_ms(c_to_stream_paused_ms(c.stream_paused_max_wait_time_ms))
}

// ---- Arrow FFI functions ----

/// Creates an Arrow Flight stream authenticated with OAuth client credentials.
///
/// `schema_ipc_bytes` must point to Arrow IPC stream bytes encoding only the schema
/// (write an empty IPC stream with just the schema message).
#[no_mangle]
pub extern "C" fn zerobus_sdk_create_arrow_stream(
    sdk: *mut CZerobusSdk,
    table_name: *const c_char,
    schema_ipc_bytes: *const u8,
    schema_ipc_len: usize,
    client_id: *const c_char,
    client_secret: *const c_char,
    options: *const CArrowStreamConfigurationOptions,
    result: *mut CResult,
) -> *mut CArrowStream {
    let sdk_ref = match validate_sdk_ptr(sdk) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return ptr::null_mut();
        }
    };

    let res = RUNTIME.block_on(async {
        let table_name_str = unsafe { c_str_to_string(table_name).map_err(|e| e.to_string())? };
        let client_id_str = unsafe { c_str_to_string(client_id).map_err(|e| e.to_string())? };
        let client_secret_str =
            unsafe { c_str_to_string(client_secret).map_err(|e| e.to_string())? };

        if schema_ipc_bytes.is_null() || schema_ipc_len == 0 {
            return Err("Schema IPC bytes are required for Arrow stream".to_string());
        }
        let schema_bytes = unsafe { std::slice::from_raw_parts(schema_ipc_bytes, schema_ipc_len) };
        let schema = ipc_bytes_to_schema(schema_bytes).map_err(|e| e.to_string())?;

        let mut builder = sdk_ref
            .stream_builder()
            .table(table_name_str)
            .oauth(client_id_str, client_secret_str)
            .arrow(schema);
        if !options.is_null() {
            builder = apply_c_arrow_stream_options(builder, unsafe { &*options });
        }

        let stream = builder.build_arrow().await.map_err(|e| e.to_string())?;

        let boxed = Box::new(stream);
        Ok::<*mut CArrowStream, String>(Box::into_raw(boxed) as *mut CArrowStream)
    });

    match res {
        Ok(ptr) => {
            write_success_result(result);
            ptr
        }
        Err(err) => {
            write_error_result(result, &err, false);
            ptr::null_mut()
        }
    }
}

/// Creates an Arrow Flight stream with a custom headers provider callback.
///
/// `schema_ipc_bytes` must point to Arrow IPC stream bytes encoding only the schema.
#[no_mangle]
pub extern "C" fn zerobus_sdk_create_arrow_stream_with_headers_provider(
    sdk: *mut CZerobusSdk,
    table_name: *const c_char,
    schema_ipc_bytes: *const u8,
    schema_ipc_len: usize,
    headers_callback: HeadersProviderCallback,
    user_data: *mut std::ffi::c_void,
    options: *const CArrowStreamConfigurationOptions,
    result: *mut CResult,
) -> *mut CArrowStream {
    let sdk_ref = match validate_sdk_ptr(sdk) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return ptr::null_mut();
        }
    };

    let res = RUNTIME.block_on(async {
        let table_name_str = unsafe { c_str_to_string(table_name).map_err(|e| e.to_string())? };

        if schema_ipc_bytes.is_null() || schema_ipc_len == 0 {
            return Err("Schema IPC bytes are required for Arrow stream".to_string());
        }
        let schema_bytes = unsafe { std::slice::from_raw_parts(schema_ipc_bytes, schema_ipc_len) };
        let schema = ipc_bytes_to_schema(schema_bytes).map_err(|e| e.to_string())?;

        let headers_provider: Arc<dyn HeadersProvider> =
            Arc::new(CallbackHeadersProvider::new(headers_callback, user_data));

        let mut builder = sdk_ref
            .stream_builder()
            .table(table_name_str)
            .headers_provider(headers_provider)
            .arrow(schema);
        if !options.is_null() {
            builder = apply_c_arrow_stream_options(builder, unsafe { &*options });
        }

        let stream = builder.build_arrow().await.map_err(|e| e.to_string())?;

        let boxed = Box::new(stream);
        Ok::<*mut CArrowStream, String>(Box::into_raw(boxed) as *mut CArrowStream)
    });

    match res {
        Ok(ptr) => {
            write_success_result(result);
            ptr
        }
        Err(err) => {
            write_error_result(result, &err, false);
            ptr::null_mut()
        }
    }
}

/// Frees an Arrow Flight stream instance.
#[no_mangle]
pub extern "C" fn zerobus_arrow_stream_free(stream: *mut CArrowStream) {
    if !stream.is_null() {
        unsafe {
            let _ = Box::from_raw(stream as *mut ZerobusArrowStream);
        }
    }
}

/// Ingests one Arrow RecordBatch supplied as Arrow IPC stream bytes.
///
/// `ipc_bytes` must be a valid Arrow IPC stream (schema + one record batch).
/// The bytes are deserialised to a RecordBatch internally. Works with all
/// compression settings. Returns the logical offset assigned to this batch, or -1 on error.
#[no_mangle]
pub extern "C" fn zerobus_arrow_stream_ingest_batch(
    stream: *mut CArrowStream,
    ipc_bytes: *const u8,
    ipc_len: usize,
    result: *mut CResult,
) -> i64 {
    if ipc_bytes.is_null() || ipc_len == 0 {
        write_error_result(result, "IPC bytes are required", false);
        return -1;
    }

    let stream_ref = match validate_arrow_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return -1;
        }
    };

    let bytes = unsafe { std::slice::from_raw_parts(ipc_bytes, ipc_len) };

    let offset_res = RUNTIME.block_on(async {
        stream_ref
            .ingest_ipc_batch(Bytes::copy_from_slice(bytes))
            .await
    });

    match offset_res {
        Ok(offset) => {
            write_success_result(result);
            offset
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            -1
        }
    }
}

/// Ingests one Arrow RecordBatch supplied as Arrow IPC stream bytes.
///
/// Equivalent to `zerobus_arrow_stream_ingest_batch`. Both functions deserialise the IPC
/// bytes to a `RecordBatch` and re-encode with the stream's compression settings, so
/// either works regardless of whether the stream was created with compression.
/// Returns the logical offset assigned to this batch, or -1 on error.
#[no_mangle]
pub extern "C" fn zerobus_arrow_stream_ingest_batch_via_record_batch(
    stream: *mut CArrowStream,
    ipc_bytes: *const u8,
    ipc_len: usize,
    result: *mut CResult,
) -> i64 {
    if ipc_bytes.is_null() || ipc_len == 0 {
        write_error_result(result, "IPC bytes are required", false);
        return -1;
    }

    let stream_ref = match validate_arrow_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return -1;
        }
    };

    let bytes = unsafe { std::slice::from_raw_parts(ipc_bytes, ipc_len) };

    let offset_res = RUNTIME.block_on(async {
        stream_ref
            .ingest_ipc_batch(bytes::Bytes::copy_from_slice(bytes))
            .await
    });

    match offset_res {
        Ok(offset) => {
            write_success_result(result);
            offset
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            -1
        }
    }
}

/// Waits until the server acknowledges the batch at the given logical offset.
#[no_mangle]
pub extern "C" fn zerobus_arrow_stream_wait_for_offset(
    stream: *mut CArrowStream,
    offset: i64,
    result: *mut CResult,
) -> bool {
    let stream_ref = match validate_arrow_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return false;
        }
    };

    let res = RUNTIME.block_on(async { stream_ref.wait_for_offset(offset).await });

    match res {
        Ok(()) => {
            write_success_result(result);
            true
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            false
        }
    }
}

/// Flushes all pending batches and waits for their acknowledgment.
#[no_mangle]
pub extern "C" fn zerobus_arrow_stream_flush(
    stream: *mut CArrowStream,
    result: *mut CResult,
) -> bool {
    let stream_ref = match validate_arrow_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return false;
        }
    };

    let res = RUNTIME.block_on(async { stream_ref.flush().await });

    match res {
        Ok(()) => {
            write_success_result(result);
            true
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            false
        }
    }
}

/// Gracefully closes the stream, flushing all pending batches first.
#[no_mangle]
pub extern "C" fn zerobus_arrow_stream_close(
    stream: *mut CArrowStream,
    result: *mut CResult,
) -> bool {
    let stream_ref = match validate_arrow_stream_ptr_mut(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return false;
        }
    };

    let res = RUNTIME.block_on(async { stream_ref.close().await });

    match res {
        Ok(()) => {
            write_success_result(result);
            true
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            false
        }
    }
}

/// Returns all unacknowledged batches from a closed or failed stream as Arrow IPC bytes.
///
/// Each batch is serialized as a self-contained Arrow IPC stream (schema + one batch).
/// The returned array must be freed with `zerobus_arrow_free_batch_array`.
#[no_mangle]
pub extern "C" fn zerobus_arrow_stream_get_unacked_batches(
    stream: *mut CArrowStream,
    result: *mut CResult,
) -> CArrowBatchArray {
    let empty = CArrowBatchArray {
        batches: ptr::null_mut(),
        lengths: ptr::null_mut(),
        count: 0,
    };

    let stream_ref = match validate_arrow_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return empty;
        }
    };

    let batches_res = RUNTIME.block_on(async { stream_ref.get_unacked_batches().await });

    match batches_res {
        Ok(batches) => {
            if batches.is_empty() {
                write_success_result(result);
                return empty;
            }

            let count = batches.len();
            let mut batch_ptrs: Vec<*mut u8> = Vec::with_capacity(count);
            let mut batch_lens: Vec<usize> = Vec::with_capacity(count);

            for batch in &batches {
                match record_batch_to_ipc_bytes(batch) {
                    Ok(bytes) => {
                        let len = bytes.len();
                        let ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8;
                        batch_ptrs.push(ptr);
                        batch_lens.push(len);
                    }
                    Err(e) => {
                        // Free already-allocated batches before returning error.
                        for (&ptr, &len) in batch_ptrs.iter().zip(batch_lens.iter()) {
                            if !ptr.is_null() && len > 0 {
                                // Safe: ptr came from Box::into_raw(bytes.into_boxed_slice()),
                                // so capacity == len.
                                unsafe {
                                    let _ =
                                        Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len));
                                }
                            }
                        }
                        write_error_result(result, &e.to_string(), false);
                        return empty;
                    }
                }
            }

            // into_boxed_slice() shrinks to fit, guaranteeing capacity == len
            // so the corresponding Box::from_raw in free_batch_array is sound.
            let ptrs_box = batch_ptrs.into_boxed_slice();
            let lens_box = batch_lens.into_boxed_slice();
            let ptrs_ptr = Box::into_raw(ptrs_box) as *mut *mut u8;
            let lens_ptr = Box::into_raw(lens_box) as *mut usize;

            write_success_result(result);
            CArrowBatchArray {
                batches: ptrs_ptr,
                lengths: lens_ptr,
                count,
            }
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            empty
        }
    }
}

/// Frees a `CArrowBatchArray` returned by `zerobus_arrow_stream_get_unacked_batches`.
#[no_mangle]
pub extern "C" fn zerobus_arrow_free_batch_array(array: CArrowBatchArray) {
    if array.count == 0 {
        return;
    }
    unsafe {
        if !array.batches.is_null() && !array.lengths.is_null() {
            // Reconstruct as Box<[T]> using the original length. This is safe because
            // the pointers were produced by Box::into_raw(vec.into_boxed_slice()),
            // which guarantees capacity == len.
            let ptrs = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                array.batches,
                array.count,
            ));
            let lens = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                array.lengths,
                array.count,
            ));
            for (&ptr, &len) in ptrs.iter().zip(lens.iter()) {
                if !ptr.is_null() && len > 0 {
                    // Each batch slice was produced by Box::into_raw(bytes.into_boxed_slice()),
                    // so capacity == len and this reconstruction is sound.
                    let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len));
                }
            }
        }
    }
}

/// Returns whether the Arrow stream has been closed.
#[no_mangle]
pub extern "C" fn zerobus_arrow_stream_is_closed(stream: *mut CArrowStream) -> bool {
    match validate_arrow_stream_ptr(stream) {
        Ok(s) => s.is_closed(),
        Err(_) => true,
    }
}

/// Returns the default Arrow stream configuration options.
#[no_mangle]
pub extern "C" fn zerobus_arrow_get_default_config() -> CArrowStreamConfigurationOptions {
    use databricks_zerobus_ingest_sdk::stream_options::defaults;
    CArrowStreamConfigurationOptions {
        max_inflight_batches: 1_000,
        recovery: defaults::RECOVERY,
        recovery_timeout_ms: defaults::RECOVERY_TIMEOUT_MS,
        recovery_backoff_ms: defaults::RECOVERY_BACKOFF_MS,
        recovery_retries: defaults::RECOVERY_RETRIES,
        server_lack_of_ack_timeout_ms: defaults::SERVER_LACK_OF_ACK_TIMEOUT_MS,
        flush_timeout_ms: defaults::FLUSH_TIMEOUT_MS,
        connection_timeout_ms: defaults::CONNECTION_TIMEOUT_MS,
        ipc_compression: -1,
        stream_paused_max_wait_time_ms: -1,
    }
}

// Global Tokio runtime for handling async Rust calls
static RUNTIME: Lazy<Runtime> =
    Lazy::new(|| Runtime::new().expect("Failed to create Tokio runtime"));

// Flag to track if logging has been initialized
static LOGGING_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize tracing subscriber for Rust logs
/// Can be controlled via RUST_LOG environment variable
/// Examples:
///   RUST_LOG=info           - Show info and above
///   RUST_LOG=debug          - Show debug and above
///   RUST_LOG=trace          - Show all logs
///   RUST_LOG=databricks_zerobus_ingest_sdk=debug - Show only SDK logs at debug level
fn init_logging() {
    if LOGGING_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
}

// Global cache for header keys to prevent memory leaks
// Header keys are typically a small set of constant strings (e.g., "Authorization", "Content-Type")
// We intern them once to avoid leaking memory on every callback
static HEADER_KEY_CACHE: Lazy<Mutex<HashSet<&'static str>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

/// Intern a header key string to prevent memory leaks
/// Only leaks memory for unique keys, not on every call
pub(crate) fn intern_header_key(key: String) -> &'static str {
    let mut cache = HEADER_KEY_CACHE.lock().unwrap();

    // Check if we already have this key
    if let Some(&existing) = cache.iter().find(|&&k| k == key.as_str()) {
        return existing;
    }

    // Only leak if it's a new key (typically happens once per unique header name)
    let static_key: &'static str = Box::leak(key.into_boxed_str());
    cache.insert(static_key);
    static_key
}

// Opaque types for Go
#[repr(C)]
pub struct CZerobusSdk {
    _private: [u8; 0],
}

#[repr(C)]
pub struct CZerobusStream {
    _private: [u8; 0],
}

// Result type for FFI calls
#[repr(C)]
pub struct CResult {
    pub success: bool,
    pub error_message: *mut c_char,
    pub is_retryable: bool,
}

/// Represents a single record (either Proto or JSON)
#[repr(C)]
pub struct CRecord {
    pub is_json: bool,
    pub data: *mut u8,
    pub data_len: usize,
}

/// Represents an array of records
#[repr(C)]
pub struct CRecordArray {
    pub records: *mut CRecord,
    pub len: usize,
}

impl CResult {
    fn success() -> Self {
        CResult {
            success: true,
            error_message: ptr::null_mut(),
            is_retryable: false,
        }
    }

    fn error(err: ZerobusError) -> Self {
        let is_retryable = err.is_retryable();
        let message = CString::new(err.to_string())
            .unwrap_or_else(|_| CString::new("Unknown error").unwrap());

        CResult {
            success: false,
            error_message: message.into_raw(),
            is_retryable,
        }
    }
}

// Configuration options
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CStreamConfigurationOptions {
    pub max_inflight_requests: usize,
    pub recovery: bool,
    pub recovery_timeout_ms: u64,
    pub recovery_backoff_ms: u64,
    pub recovery_retries: u32,
    pub server_lack_of_ack_timeout_ms: u64,
    pub flush_timeout_ms: u64,
    pub record_type: i32,
    pub stream_paused_max_wait_time_ms: u64,
    pub has_stream_paused_max_wait_time_ms: bool,
    pub callback_max_wait_time_ms: u64,
    pub has_callback_max_wait_time_ms: bool,
}

// Helper to convert C string to Rust String
unsafe fn c_str_to_string(c_str: *const c_char) -> Result<String, &'static str> {
    if c_str.is_null() {
        return Err("Null pointer passed");
    }
    CStr::from_ptr(c_str)
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| "Invalid UTF-8 string")
}

/// A single header key-value pair for C FFI
#[repr(C)]
pub struct CHeader {
    pub key: *mut c_char,
    pub value: *mut c_char,
}

/// A collection of headers returned from Go callback
#[repr(C)]
pub struct CHeaders {
    pub headers: *mut CHeader,
    pub count: usize,
    pub error_message: *mut c_char,
}

/// Function pointer type for the headers provider callback
/// The callback should return a CHeaders struct
/// The caller is responsible for freeing the returned CHeaders using zerobus_free_headers
pub type HeadersProviderCallback = extern "C" fn(user_data: *mut std::ffi::c_void) -> CHeaders;

/// Free headers returned from callback
#[no_mangle]
pub extern "C" fn zerobus_free_headers(headers: CHeaders) {
    if !headers.headers.is_null() {
        unsafe {
            let headers_slice = std::slice::from_raw_parts_mut(headers.headers, headers.count);
            for header in headers_slice {
                if !header.key.is_null() {
                    let _ = CString::from_raw(header.key);
                }
                if !header.value.is_null() {
                    let _ = CString::from_raw(header.value);
                }
            }
            libc::free(headers.headers as *mut std::ffi::c_void);
        }
    }
    if !headers.error_message.is_null() {
        unsafe {
            let _ = CString::from_raw(headers.error_message);
        }
    }
}

/// Rust struct that wraps a Go callback and implements HeadersProvider
pub(crate) struct CallbackHeadersProvider {
    callback: HeadersProviderCallback,
    user_data: *mut std::ffi::c_void,
    in_use: AtomicBool, // Track concurrent access to detect thread-safety issues
}

impl CallbackHeadersProvider {
    pub(crate) fn new(callback: HeadersProviderCallback, user_data: *mut std::ffi::c_void) -> Self {
        Self {
            callback,
            user_data,
            in_use: AtomicBool::new(false),
        }
    }
}

// Safety: We assume the Go callback is thread-safe, but we validate at runtime
unsafe impl Send for CallbackHeadersProvider {}
unsafe impl Sync for CallbackHeadersProvider {}

#[async_trait]
impl HeadersProvider for CallbackHeadersProvider {
    async fn get_headers(&self) -> ZerobusResult<HashMap<&'static str, String>> {
        // Check for concurrent access (indicates thread-safety issue)
        if self.in_use.swap(true, Ordering::SeqCst) {
            return Err(ZerobusError::InvalidArgument(
                "Concurrent headers provider callback detected - Go callback must be thread-safe"
                    .to_string(),
            ));
        }

        // Call the Go callback (synchronous)
        let c_headers = (self.callback)(self.user_data);

        // Release the lock before processing
        self.in_use.store(false, Ordering::SeqCst);

        // Check for error
        if !c_headers.error_message.is_null() {
            let error_str = unsafe {
                CStr::from_ptr(c_headers.error_message)
                    .to_string_lossy()
                    .into_owned()
            };
            zerobus_free_headers(c_headers);
            return Err(ZerobusError::InvalidArgument(format!(
                "Headers provider error: {}",
                error_str
            )));
        }

        // Convert C headers to Rust HashMap
        let mut headers = HashMap::new();
        if !c_headers.headers.is_null() && c_headers.count > 0 {
            unsafe {
                let headers_slice = std::slice::from_raw_parts(c_headers.headers, c_headers.count);
                for header in headers_slice {
                    if !header.key.is_null() && !header.value.is_null() {
                        let key = CStr::from_ptr(header.key).to_string_lossy().into_owned();
                        let value = CStr::from_ptr(header.value).to_string_lossy().into_owned();

                        // Use interned keys to minimize memory leaks
                        // Only unique header names are leaked (typically < 10 strings for lifetime of process)
                        let static_key = intern_header_key(key);
                        headers.insert(static_key, value);
                    }
                }
            }
        }

        zerobus_free_headers(c_headers);
        Ok(headers)
    }
}

// ============================================================================
// SDK Functions
// ============================================================================

/// Safe wrapper to validate SDK pointer
pub(crate) fn validate_sdk_ptr<'a>(sdk: *mut CZerobusSdk) -> Result<&'a ZerobusSdk, &'static str> {
    if sdk.is_null() {
        return Err("SDK pointer is null");
    }
    // Still unsafe, but centralized and validated
    unsafe { Ok(&*(sdk as *const ZerobusSdk)) }
}

/// Safe wrapper to validate stream pointer
pub(crate) fn validate_stream_ptr<'a>(
    stream: *mut CZerobusStream,
) -> Result<&'a ZerobusStream, &'static str> {
    if stream.is_null() {
        return Err("Stream pointer is null");
    }
    unsafe { Ok(&*(stream as *const ZerobusStream)) }
}

/// Safe wrapper to validate mutable stream pointer
pub(crate) fn validate_stream_ptr_mut<'a>(
    stream: *mut CZerobusStream,
) -> Result<&'a mut ZerobusStream, &'static str> {
    if stream.is_null() {
        return Err("Stream pointer is null");
    }
    unsafe { Ok(&mut *(stream as *mut ZerobusStream)) }
}

/// Helper to write error result
pub(crate) fn write_error_result(result: *mut CResult, message: &str, is_retryable: bool) {
    if !result.is_null() {
        unsafe {
            *result = CResult {
                success: false,
                error_message: CString::new(message)
                    .unwrap_or_else(|_| CString::new("Error message contains null byte").unwrap())
                    .into_raw(),
                is_retryable,
            };
        }
    }
}

/// Helper to write success result
pub(crate) fn write_success_result(result: *mut CResult) {
    if !result.is_null() {
        unsafe {
            *result = CResult::success();
        }
    }
}

// ============================================================================
// ZerobusSdkBuilder FFI
// ============================================================================
//
// C-builder mirroring the Rust `ZerobusSdkBuilder`. New options are added as
// additive setter functions — no ABI breaks.
//
// Lifecycle: `_new` → zero or more `_<setter>` calls → `_build` (consumes) or
// `_free` (abandon). Single-owner; not safe to share across threads.

/// Opaque handle for an SDK builder. Allocated by `_new`, consumed by
/// `_build`, or dropped by `_free`. Must not be used after either finalizer.
#[repr(C)]
pub struct CZerobusSdkBuilder {
    _private: [u8; 0],
}

/// Concrete type behind `*mut CZerobusSdkBuilder`. All cast sites in this
/// module must agree on this alias.
type SdkBuilderAlloc = ZerobusSdkBuilder;

/// SAFETY: `b` must be a valid pointer from `_new` that hasn't been consumed
/// or freed. `mem::take` keeps the slot valid even if `f` panics.
unsafe fn with_builder<F>(b: *mut CZerobusSdkBuilder, f: F)
where
    F: FnOnce(ZerobusSdkBuilder) -> ZerobusSdkBuilder,
{
    if b.is_null() {
        return;
    }
    let slot = &mut *(b as *mut SdkBuilderAlloc);
    let taken = std::mem::take(slot);
    *slot = f(taken);
}

/// Allocates a new SDK builder. Must be terminated by exactly one of
/// `_build` or `_free`.
#[no_mangle]
pub extern "C" fn zerobus_sdk_builder_new() -> *mut CZerobusSdkBuilder {
    init_logging();
    let boxed: Box<SdkBuilderAlloc> = Box::new(ZerobusSdk::builder());
    Box::into_raw(boxed) as *mut CZerobusSdkBuilder
}

/// Sets the Zerobus gRPC endpoint URL (required). No-op on null.
#[no_mangle]
pub extern "C" fn zerobus_sdk_builder_endpoint(
    builder: *mut CZerobusSdkBuilder,
    value: *const c_char,
) {
    if value.is_null() {
        return;
    }
    let s = match unsafe { c_str_to_string(value) } {
        Ok(s) => s,
        Err(_) => return,
    };
    unsafe { with_builder(builder, |b| b.endpoint(s)) }
}

/// Sets the Unity Catalog URL. Optional with a custom headers provider.
/// No-op on null.
#[no_mangle]
pub extern "C" fn zerobus_sdk_builder_unity_catalog_url(
    builder: *mut CZerobusSdkBuilder,
    value: *const c_char,
) {
    if value.is_null() {
        return;
    }
    let s = match unsafe { c_str_to_string(value) } {
        Ok(s) => s,
        Err(_) => return,
    };
    unsafe { with_builder(builder, |b| b.unity_catalog_url(s)) }
}

/// Overrides the SDK prefix of the `user-agent` header (default
/// `zerobus-sdk-rs/<version>`). Wrappers pass their own identifier here.
/// Null and empty values are no-ops.
#[no_mangle]
pub extern "C" fn zerobus_sdk_builder_sdk_identifier(
    builder: *mut CZerobusSdkBuilder,
    value: *const c_char,
) {
    if value.is_null() {
        return;
    }
    let s = match unsafe { c_str_to_string(value) } {
        Ok(s) if !s.is_empty() => s,
        _ => return,
    };
    unsafe { with_builder(builder, |b| b.sdk_identifier(s)) }
}

/// Appends an application identifier to the `user-agent` header. Wire value
/// becomes `<sdk_identifier> <application_name>`. Null and empty values are
/// no-ops.
#[no_mangle]
pub extern "C" fn zerobus_sdk_builder_application_name(
    builder: *mut CZerobusSdkBuilder,
    value: *const c_char,
) {
    if value.is_null() {
        return;
    }
    let s = match unsafe { c_str_to_string(value) } {
        Ok(s) if !s.is_empty() => s,
        _ => return,
    };
    unsafe { with_builder(builder, |b| b.application_name(s)) }
}

/// Selects a no-TLS gRPC channel. TLS is on by default.
#[no_mangle]
pub extern "C" fn zerobus_sdk_builder_disable_tls(builder: *mut CZerobusSdkBuilder) {
    unsafe { with_builder(builder, |b| b.tls_config(Arc::new(NoTlsConfig))) }
}

/// Consumes the builder and returns a `CZerobusSdk*`, or NULL on error.
/// Frees the builder on both paths — any further use of the pointer is
/// undefined behavior. Null `builder` writes an error to `result`.
#[no_mangle]
pub extern "C" fn zerobus_sdk_builder_build(
    builder: *mut CZerobusSdkBuilder,
    result: *mut CResult,
) -> *mut CZerobusSdk {
    if builder.is_null() {
        write_error_result(result, "Builder pointer is null", false);
        return ptr::null_mut();
    }
    // Reclaim ownership of the builder Box so it is dropped on every path,
    // mirroring the Rust builder's consume-on-build semantics.
    let inner = *unsafe { Box::from_raw(builder as *mut SdkBuilderAlloc) };
    match inner.build() {
        Ok(sdk) => {
            write_success_result(result);
            Box::into_raw(Box::new(sdk)) as *mut CZerobusSdk
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            ptr::null_mut()
        }
    }
}

/// Drops an unconsumed builder. No-op on null.
#[no_mangle]
pub extern "C" fn zerobus_sdk_builder_free(builder: *mut CZerobusSdkBuilder) {
    if !builder.is_null() {
        unsafe {
            let _ = Box::from_raw(builder as *mut SdkBuilderAlloc);
        }
    }
}

/// Creates a new ZerobusSdk with default user-agent and TLS settings.
///
/// Retained for ABI back-compat with v1.2.x; new code should use the
/// `zerobus_sdk_builder_*` API. Does not infer TLS state from the endpoint
/// scheme — callers needing a plain-HTTP channel must use the builder API.
///
/// Returns NULL on error; see `result` for details.
#[no_mangle]
pub extern "C" fn zerobus_sdk_new(
    zerobus_endpoint: *const c_char,
    unity_catalog_url: *const c_char,
    result: *mut CResult,
) -> *mut CZerobusSdk {
    let builder = zerobus_sdk_builder_new();
    zerobus_sdk_builder_endpoint(builder, zerobus_endpoint);
    zerobus_sdk_builder_unity_catalog_url(builder, unity_catalog_url);
    zerobus_sdk_builder_build(builder, result)
}

/// Free the SDK instance
#[no_mangle]
pub extern "C" fn zerobus_sdk_free(sdk: *mut CZerobusSdk) {
    if !sdk.is_null() {
        unsafe {
            let _ = Box::from_raw(sdk as *mut ZerobusSdk);
        }
    }
}

/// Set whether to use TLS for connections.
///
/// Deprecated: This function is a no-op. TLS is now controlled via the `TlsConfig`
/// trait passed to the SDK builder. This function is retained for ABI compatibility.
#[no_mangle]
pub extern "C" fn zerobus_sdk_set_use_tls(_sdk: *mut CZerobusSdk, _use_tls: bool) {}

/// Create a stream with OAuth authentication
/// descriptor_proto_bytes: protobuf-encoded DescriptorProto (can be NULL for JSON streams)
#[no_mangle]
pub extern "C" fn zerobus_sdk_create_stream(
    sdk: *mut CZerobusSdk,
    table_name: *const c_char,
    descriptor_proto_bytes: *const u8,
    descriptor_proto_len: usize,
    client_id: *const c_char,
    client_secret: *const c_char,
    options: *const CStreamConfigurationOptions,
    result: *mut CResult,
) -> *mut CZerobusStream {
    let sdk_ref = match validate_sdk_ptr(sdk) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return ptr::null_mut();
        }
    };

    let res = RUNTIME.block_on(async {
        let table_name_str = unsafe { c_str_to_string(table_name).map_err(|e| e.to_string())? };
        let client_id_str = unsafe { c_str_to_string(client_id).map_err(|e| e.to_string())? };
        let client_secret_str =
            unsafe { c_str_to_string(client_secret).map_err(|e| e.to_string())? };

        let descriptor_proto = if !descriptor_proto_bytes.is_null() && descriptor_proto_len > 0 {
            let bytes =
                unsafe { std::slice::from_raw_parts(descriptor_proto_bytes, descriptor_proto_len) };
            Some(prost_types::DescriptorProto::decode(bytes).map_err(|e| e.to_string())?)
        } else {
            None
        };

        let c_opts = if !options.is_null() {
            Some(unsafe { &*options })
        } else {
            None
        };
        let record_type = c_opts
            .map(|c| c_record_type(c.record_type))
            .unwrap_or(RecordType::Proto);

        let base = sdk_ref
            .stream_builder()
            .table(table_name_str)
            .oauth(client_id_str, client_secret_str);
        let mut builder = match record_type {
            RecordType::Proto => {
                let desc = descriptor_proto.ok_or_else(|| {
                    "Proto descriptor is required for Proto record type".to_string()
                })?;
                base.compiled_proto(desc)
            }
            RecordType::Json => base.json(),
            RecordType::Unspecified => return Err("Record type is not specified".to_string()),
        };
        if let Some(c) = c_opts {
            builder = apply_c_stream_options(builder, c);
        }

        let stream = builder.build().await.map_err(|e| e.to_string())?;

        let arc = Arc::new(stream);
        Ok::<*mut CZerobusStream, String>(Arc::into_raw(arc) as *mut CZerobusStream)
    });

    match res {
        Ok(stream_ptr) => {
            write_success_result(result);
            stream_ptr
        }
        Err(err) => {
            write_error_result(result, &err, false);
            ptr::null_mut()
        }
    }
}

/// Create a stream with a custom headers provider callback
/// This allows you to provide custom authentication headers via a Go callback function
#[no_mangle]
pub extern "C" fn zerobus_sdk_create_stream_with_headers_provider(
    sdk: *mut CZerobusSdk,
    table_name: *const c_char,
    descriptor_proto_bytes: *const u8,
    descriptor_proto_len: usize,
    headers_callback: HeadersProviderCallback,
    user_data: *mut std::ffi::c_void,
    options: *const CStreamConfigurationOptions,
    result: *mut CResult,
) -> *mut CZerobusStream {
    let sdk_ref = match validate_sdk_ptr(sdk) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return ptr::null_mut();
        }
    };

    let res = RUNTIME.block_on(async {
        let table_name_str = unsafe { c_str_to_string(table_name).map_err(|e| e.to_string())? };

        let descriptor_proto = if !descriptor_proto_bytes.is_null() && descriptor_proto_len > 0 {
            let bytes =
                unsafe { std::slice::from_raw_parts(descriptor_proto_bytes, descriptor_proto_len) };
            Some(prost_types::DescriptorProto::decode(bytes).map_err(|e| e.to_string())?)
        } else {
            None
        };

        let c_opts = if !options.is_null() {
            Some(unsafe { &*options })
        } else {
            None
        };
        let record_type = c_opts
            .map(|c| c_record_type(c.record_type))
            .unwrap_or(RecordType::Proto);

        let headers_provider: Arc<dyn HeadersProvider> =
            Arc::new(CallbackHeadersProvider::new(headers_callback, user_data));

        let base = sdk_ref
            .stream_builder()
            .table(table_name_str)
            .headers_provider(headers_provider);
        let mut builder = match record_type {
            RecordType::Proto => {
                let desc = descriptor_proto.ok_or_else(|| {
                    "Proto descriptor is required for Proto record type".to_string()
                })?;
                base.compiled_proto(desc)
            }
            RecordType::Json => base.json(),
            RecordType::Unspecified => return Err("Record type is not specified".to_string()),
        };
        if let Some(c) = c_opts {
            builder = apply_c_stream_options(builder, c);
        }

        let stream = builder.build().await.map_err(|e| e.to_string())?;

        let arc = Arc::new(stream);
        Ok::<*mut CZerobusStream, String>(Arc::into_raw(arc) as *mut CZerobusStream)
    });

    match res {
        Ok(stream_ptr) => {
            write_success_result(result);
            stream_ptr
        }
        Err(err) => {
            write_error_result(result, &err, false);
            ptr::null_mut()
        }
    }
}

/// Free a stream instance
#[no_mangle]
pub extern "C" fn zerobus_stream_free(stream: *mut CZerobusStream) {
    if !stream.is_null() {
        unsafe {
            // Reconstruct the Arc and drop it. If nowait tasks still hold clones,
            // the stream is not freed until the last Arc is dropped.
            let _ = Arc::from_raw(stream as *const ZerobusStream);
        }
    }
}

/// Ingest a record (protobuf encoded)
/// Returns the offset directly
/// Returns -1 on error
#[no_mangle]
pub extern "C" fn zerobus_stream_ingest_proto_record(
    stream: *mut CZerobusStream,
    data: *const u8,
    data_len: usize,
    result: *mut CResult,
) -> i64 {
    if data.is_null() {
        write_error_result(result, "Invalid data pointer", false);
        return -1;
    }

    let stream_ref = match validate_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return -1;
        }
    };

    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    let data_vec = data_slice.to_vec();

    // Queue the record and get the offset directly
    let offset_res = RUNTIME.block_on(async {
        let payload = EncodedRecord::Proto(data_vec);
        stream_ref.ingest_record_offset(payload).await
    });

    match offset_res {
        Ok(offset) => {
            write_success_result(result);
            offset
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            -1
        }
    }
}

/// Ingest a JSON record
/// Returns the offset directly
/// Returns -1 on error
#[no_mangle]
pub extern "C" fn zerobus_stream_ingest_json_record(
    stream: *mut CZerobusStream,
    json_data: *const c_char,
    result: *mut CResult,
) -> i64 {
    let stream_ref = match validate_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return -1;
        }
    };

    let json_str = match unsafe { c_str_to_string(json_data) } {
        Ok(s) => s,
        Err(e) => {
            write_error_result(result, e, false);
            return -1;
        }
    };

    // Queue the record and get the offset directly
    let offset_res = RUNTIME.block_on(async {
        let payload = EncodedRecord::Json(json_str);
        stream_ref.ingest_record_offset(payload).await
    });

    match offset_res {
        Ok(offset) => {
            write_success_result(result);
            offset
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            -1
        }
    }
}

/// Ingest a batch of protobuf records
/// Returns the offset of the last record in the batch, or -1 on error
/// Returns -2 if batch is empty
#[no_mangle]
pub extern "C" fn zerobus_stream_ingest_proto_records(
    stream: *mut CZerobusStream,
    records: *const *const u8,
    record_lens: *const usize,
    num_records: usize,
    result: *mut CResult,
) -> i64 {
    if records.is_null() || record_lens.is_null() {
        write_error_result(result, "Invalid records pointer", false);
        return -1;
    }

    if num_records == 0 {
        write_success_result(result);
        return -2; // Empty batch
    }

    let stream_ref = match validate_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return -1;
        }
    };

    // Convert array of C pointers to Vec<Vec<u8>>
    let records_vec: Vec<Vec<u8>> = unsafe {
        let records_slice = std::slice::from_raw_parts(records, num_records);
        let lens_slice = std::slice::from_raw_parts(record_lens, num_records);

        records_slice
            .iter()
            .zip(lens_slice.iter())
            .map(|(ptr, len)| {
                let data_slice = std::slice::from_raw_parts(*ptr, *len);
                data_slice.to_vec()
            })
            .collect()
    };

    // Queue the records and get the offset
    let offset_res = RUNTIME.block_on(async {
        let payloads: Vec<EncodedRecord> =
            records_vec.into_iter().map(EncodedRecord::Proto).collect();
        stream_ref.ingest_records_offset(payloads).await
    });

    match offset_res {
        Ok(Some(offset)) => {
            write_success_result(result);
            offset
        }
        Ok(None) => {
            write_success_result(result);
            -2 // Empty batch
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            -1
        }
    }
}

/// Ingest a batch of JSON records
/// Returns the offset of the last record in the batch, or -1 on error
/// Returns -2 if batch is empty
#[no_mangle]
pub extern "C" fn zerobus_stream_ingest_json_records(
    stream: *mut CZerobusStream,
    json_records: *const *const c_char,
    num_records: usize,
    result: *mut CResult,
) -> i64 {
    if json_records.is_null() {
        write_error_result(result, "Invalid records pointer", false);
        return -1;
    }

    if num_records == 0 {
        write_success_result(result);
        return -2; // Empty batch
    }

    let stream_ref = match validate_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return -1;
        }
    };

    // Convert array of C strings to Vec<String>
    let json_vec: Result<Vec<String>, _> = unsafe {
        let json_slice = std::slice::from_raw_parts(json_records, num_records);
        json_slice.iter().map(|ptr| c_str_to_string(*ptr)).collect()
    };

    let json_vec = match json_vec {
        Ok(v) => v,
        Err(e) => {
            write_error_result(result, e, false);
            return -1;
        }
    };

    // Queue the records and get the offset
    let offset_res = RUNTIME.block_on(async {
        let payloads: Vec<EncodedRecord> = json_vec.into_iter().map(EncodedRecord::Json).collect();
        stream_ref.ingest_records_offset(payloads).await
    });

    match offset_res {
        Ok(Some(offset)) => {
            write_success_result(result);
            offset
        }
        Ok(None) => {
            write_success_result(result);
            -2 // Empty batch
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            -1
        }
    }
}

/// Clones the `Arc<ZerobusStream>` from a raw `CZerobusStream` pointer without
/// consuming the pointer. The caller retains ownership of the original pointer;
/// the returned `Arc` will keep the stream alive until it is dropped.
///
/// # Safety
/// `stream` must be a non-null pointer produced by `zerobus_sdk_create_stream` or
/// `zerobus_sdk_create_stream_with_headers_provider` and must not have been freed.
unsafe fn clone_stream_arc(stream: *mut CZerobusStream) -> Arc<ZerobusStream> {
    Arc::increment_strong_count(stream as *const ZerobusStream);
    Arc::from_raw(stream as *const ZerobusStream)
}

/// Ingest a protobuf record without waiting for the record to be queued (fire-and-forget).
///
/// Spawns a background task to queue the record and returns immediately.
/// The result only reflects argument validation errors; ingestion errors are silently ignored.
///
/// # Safety
/// The stream must remain valid until all background tasks spawned by this function complete.
#[no_mangle]
pub extern "C" fn zerobus_stream_ingest_proto_record_nowait(
    stream: *mut CZerobusStream,
    data: *const u8,
    data_len: usize,
    result: *mut CResult,
) {
    if data.is_null() {
        write_error_result(result, "Invalid data pointer", false);
        return;
    }

    if let Err(msg) = validate_stream_ptr(stream) {
        write_error_result(result, msg, false);
        return;
    }

    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    let data_vec = data_slice.to_vec();
    let stream_arc = unsafe { clone_stream_arc(stream) };

    RUNTIME.spawn(async move {
        let payload = EncodedRecord::Proto(data_vec);
        let _ = stream_arc.ingest_record_offset(payload).await;
    });

    write_success_result(result);
}

/// Ingest a JSON record without waiting for the record to be queued (fire-and-forget).
///
/// Spawns a background task to queue the record and returns immediately.
/// The result only reflects argument validation errors; ingestion errors are silently ignored.
///
/// # Safety
/// The stream must remain valid until all background tasks spawned by this function complete.
#[no_mangle]
pub extern "C" fn zerobus_stream_ingest_json_record_nowait(
    stream: *mut CZerobusStream,
    json_data: *const c_char,
    result: *mut CResult,
) {
    if let Err(msg) = validate_stream_ptr(stream) {
        write_error_result(result, msg, false);
        return;
    }

    let json_str = match unsafe { c_str_to_string(json_data) } {
        Ok(s) => s,
        Err(e) => {
            write_error_result(result, e, false);
            return;
        }
    };

    let stream_arc = unsafe { clone_stream_arc(stream) };

    RUNTIME.spawn(async move {
        let payload = EncodedRecord::Json(json_str);
        let _ = stream_arc.ingest_record_offset(payload).await;
    });

    write_success_result(result);
}

/// Ingest a batch of protobuf records without waiting (fire-and-forget).
///
/// Copies all record data before spawning the background task, so the caller's
/// memory is safe to release immediately after this function returns.
///
/// # Safety
/// The stream must remain valid until all background tasks spawned by this function complete.
#[no_mangle]
pub extern "C" fn zerobus_stream_ingest_proto_records_nowait(
    stream: *mut CZerobusStream,
    records: *const *const u8,
    record_lens: *const usize,
    num_records: usize,
    result: *mut CResult,
) {
    if records.is_null() || record_lens.is_null() {
        write_error_result(result, "Invalid records pointer", false);
        return;
    }

    if let Err(msg) = validate_stream_ptr(stream) {
        write_error_result(result, msg, false);
        return;
    }

    if num_records == 0 {
        write_success_result(result);
        return;
    }

    let records_vec: Vec<Vec<u8>> = unsafe {
        let records_slice = std::slice::from_raw_parts(records, num_records);
        let lens_slice = std::slice::from_raw_parts(record_lens, num_records);
        records_slice
            .iter()
            .zip(lens_slice.iter())
            .map(|(ptr, len)| std::slice::from_raw_parts(*ptr, *len).to_vec())
            .collect()
    };

    let stream_arc = unsafe { clone_stream_arc(stream) };

    RUNTIME.spawn(async move {
        let payloads: Vec<EncodedRecord> =
            records_vec.into_iter().map(EncodedRecord::Proto).collect();
        let _ = stream_arc.ingest_records_offset(payloads).await;
    });

    write_success_result(result);
}

/// Ingest a batch of JSON records without waiting (fire-and-forget).
///
/// Copies all strings before spawning the background task, so the caller's
/// memory is safe to release immediately after this function returns.
///
/// # Safety
/// The stream must remain valid until all background tasks spawned by this function complete.
#[no_mangle]
pub extern "C" fn zerobus_stream_ingest_json_records_nowait(
    stream: *mut CZerobusStream,
    json_records: *const *const c_char,
    num_records: usize,
    result: *mut CResult,
) {
    if json_records.is_null() {
        write_error_result(result, "Invalid records pointer", false);
        return;
    }

    if let Err(msg) = validate_stream_ptr(stream) {
        write_error_result(result, msg, false);
        return;
    }

    if num_records == 0 {
        write_success_result(result);
        return;
    }

    let json_vec: Result<Vec<String>, _> = unsafe {
        let json_slice = std::slice::from_raw_parts(json_records, num_records);
        json_slice.iter().map(|ptr| c_str_to_string(*ptr)).collect()
    };

    let json_vec = match json_vec {
        Ok(v) => v,
        Err(e) => {
            write_error_result(result, e, false);
            return;
        }
    };

    let stream_arc = unsafe { clone_stream_arc(stream) };

    RUNTIME.spawn(async move {
        let payloads: Vec<EncodedRecord> = json_vec.into_iter().map(EncodedRecord::Json).collect();
        let _ = stream_arc.ingest_records_offset(payloads).await;
    });

    write_success_result(result);
}

/// Wait for a specific offset to be acknowledged by the server
#[no_mangle]
pub extern "C" fn zerobus_stream_wait_for_offset(
    stream: *mut CZerobusStream,
    offset: i64,
    result: *mut CResult,
) -> bool {
    let stream_ref = match validate_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return false;
        }
    };

    let res = RUNTIME.block_on(async { stream_ref.wait_for_offset(offset).await });

    match res {
        Ok(()) => {
            write_success_result(result);
            true
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            false
        }
    }
}

/// Flush all pending records
#[no_mangle]
pub extern "C" fn zerobus_stream_flush(stream: *mut CZerobusStream, result: *mut CResult) -> bool {
    let stream_ref = match validate_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return false;
        }
    };

    let res = RUNTIME.block_on(async { stream_ref.flush().await });

    match res {
        Ok(_) => {
            write_success_result(result);
            true
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            false
        }
    }
}

/// Get unacknowledged records from a closed stream
/// Returns a CRecordArray that must be freed with zerobus_free_record_array
#[no_mangle]
pub extern "C" fn zerobus_stream_get_unacked_records(
    stream: *mut CZerobusStream,
    result: *mut CResult,
) -> CRecordArray {
    let stream_ref = match validate_stream_ptr(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return CRecordArray {
                records: ptr::null_mut(),
                len: 0,
            };
        }
    };

    let records_res = RUNTIME.block_on(async { stream_ref.get_unacked_records().await });

    match records_res {
        Ok(records_iter) => {
            // Collect into Vec
            let records_vec: Vec<EncodedRecord> = records_iter.collect();
            let len = records_vec.len();

            // Convert to CRecords
            let mut c_records: Vec<CRecord> = records_vec
                .into_iter()
                .map(|record| match record {
                    EncodedRecord::Proto(data) => {
                        let data_len = data.len();
                        let data_ptr = Box::into_raw(data.into_boxed_slice()) as *mut u8;
                        CRecord {
                            is_json: false,
                            data: data_ptr,
                            data_len,
                        }
                    }
                    EncodedRecord::Json(json_str) => {
                        let bytes = json_str.into_bytes();
                        let data_len = bytes.len();
                        let data_ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8;
                        CRecord {
                            is_json: true,
                            data: data_ptr,
                            data_len,
                        }
                    }
                })
                .collect();

            let records_ptr = c_records.as_mut_ptr();
            std::mem::forget(c_records); // Don't drop, Go will call free

            write_success_result(result);
            CRecordArray {
                records: records_ptr,
                len,
            }
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            CRecordArray {
                records: ptr::null_mut(),
                len: 0,
            }
        }
    }
}

/// Free a CRecordArray returned by zerobus_stream_get_unacked_records
#[no_mangle]
pub extern "C" fn zerobus_free_record_array(array: CRecordArray) {
    if array.records.is_null() || array.len == 0 {
        return;
    }

    unsafe {
        let records_vec = Vec::from_raw_parts(array.records, array.len, array.len);
        for record in records_vec {
            if !record.data.is_null() && record.data_len > 0 {
                let _ = Vec::from_raw_parts(record.data, record.data_len, record.data_len);
            }
        }
    }
}

/// Close the stream gracefully
#[no_mangle]
pub extern "C" fn zerobus_stream_close(stream: *mut CZerobusStream, result: *mut CResult) -> bool {
    let stream_ref = match validate_stream_ptr_mut(stream) {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return false;
        }
    };

    let res = RUNTIME.block_on(async { stream_ref.close().await });

    match res {
        Ok(_) => {
            write_success_result(result);
            true
        }
        Err(err) => {
            if !result.is_null() {
                unsafe {
                    *result = CResult::error(err);
                }
            }
            false
        }
    }
}

/// Free error message string
#[no_mangle]
pub extern "C" fn zerobus_free_error_message(message: *mut c_char) {
    if !message.is_null() {
        unsafe {
            let _ = CString::from_raw(message);
        }
    }
}

/// Get default stream configuration options
#[no_mangle]
pub extern "C" fn zerobus_get_default_config() -> CStreamConfigurationOptions {
    use databricks_zerobus_ingest_sdk::stream_options::defaults;
    CStreamConfigurationOptions {
        max_inflight_requests: 1_000_000,
        recovery: defaults::RECOVERY,
        recovery_timeout_ms: defaults::RECOVERY_TIMEOUT_MS,
        recovery_backoff_ms: defaults::RECOVERY_BACKOFF_MS,
        recovery_retries: defaults::RECOVERY_RETRIES,
        server_lack_of_ack_timeout_ms: defaults::SERVER_LACK_OF_ACK_TIMEOUT_MS,
        flush_timeout_ms: defaults::FLUSH_TIMEOUT_MS,
        record_type: 1, // RecordType::Proto
        stream_paused_max_wait_time_ms: 0,
        has_stream_paused_max_wait_time_ms: false,
        callback_max_wait_time_ms: defaults::CALLBACK_MAX_WAIT_TIME_MS,
        has_callback_max_wait_time_ms: true,
    }
}

// ============================================================================
// Dynamic Protobuf FFI
// ============================================================================
//
// Pure-C consumers can build a protobuf descriptor from Unity Catalog metadata
// and encode JSON records to protobuf bytes without a companion Rust crate.
// Lifecycle: `_from_uc_json` → `_descriptor_bytes` / `_encode_json` → `_free`.

/// Opaque handle to a table's protobuf schema: its serialized descriptor plus a
/// prepared encoder. C code only ever holds a pointer to it; the backing
/// allocation is owned by the SDK and released by zerobus_proto_schema_free.
#[repr(C)]
pub struct CZerobusProtoSchema {
    _private: [u8; 0],
}

/// Concrete type behind `*mut CZerobusProtoSchema`.
struct ProtoSchema {
    /// Serialized `DescriptorProto` bytes (passed to `zerobus_sdk_create_stream`).
    descriptor_bytes: Vec<u8>,
    /// Message descriptor for encoding JSON records to protobuf.
    message: MessageDescriptor,
}

/// Null-check a schema handle and borrow the [`ProtoSchema`] behind it.
///
/// # Safety
///
/// `schema` must be null or a live handle from
/// [`zerobus_proto_schema_from_uc_json`]. The caller must not free the handle
/// (via [`zerobus_proto_schema_free`]) for the lifetime of the returned borrow.
unsafe fn proto_schema_ref<'a>(
    schema: *const CZerobusProtoSchema,
) -> Result<&'a ProtoSchema, &'static str> {
    if schema.is_null() {
        return Err("Proto schema pointer is null");
    }
    Ok(&*(schema as *const ProtoSchema))
}

/// Builds a [`ProtoSchema`] from Unity Catalog table-metadata JSON.
fn build_proto_schema(uc_table_json: &str) -> Result<ProtoSchema, String> {
    let schema: UcTableSchema = serde_json::from_str(uc_table_json)
        .map_err(|e| format!("failed to parse Unity Catalog table JSON: {e}"))?;
    let descriptor = descriptor_from_uc_schema(&schema).map_err(|e| e.to_string())?;
    let descriptor_bytes = descriptor.encode_to_vec();
    let message_name = descriptor.name().to_string();

    let file = prost_types::FileDescriptorProto {
        name: Some("zerobus_dynamic.proto".to_string()),
        message_type: vec![descriptor],
        ..Default::default()
    };
    let mut pool = DescriptorPool::new();
    pool.add_file_descriptor_proto(file)
        .map_err(|e| format!("failed to build descriptor pool: {e}"))?;
    // No package on the synthetic file, so the fully-qualified name is the
    // bare message name.
    let message = pool
        .get_message_by_name(&message_name)
        .ok_or_else(|| format!("message '{message_name}' not found in descriptor pool"))?;

    Ok(ProtoSchema {
        descriptor_bytes,
        message,
    })
}

/// Build a protobuf schema from Unity Catalog table metadata JSON.
/// Returns NULL on error; free with `zerobus_proto_schema_free`.
#[no_mangle]
pub extern "C" fn zerobus_proto_schema_from_uc_json(
    uc_table_json: *const c_char,
    result: *mut CResult,
) -> *mut CZerobusProtoSchema {
    let json = match unsafe { c_str_to_string(uc_table_json) } {
        Ok(s) => s,
        Err(e) => {
            write_error_result(result, e, false);
            return ptr::null_mut();
        }
    };

    match build_proto_schema(&json) {
        Ok(schema) => {
            write_success_result(result);
            // Hand ownership of the allocation to C as a raw pointer; it is
            // reclaimed by zerobus_proto_schema_free.
            Box::into_raw(Box::new(schema)) as *mut CZerobusProtoSchema
        }
        Err(err) => {
            write_error_result(result, &err, false);
            ptr::null_mut()
        }
    }
}

/// Borrow the serialized descriptor bytes. Valid until `zerobus_proto_schema_free`.
/// Pass directly to `zerobus_sdk_create_stream`.
///
/// `out_len` is required: the bytes are not null-terminated, so the caller needs
/// the length to read them. Returns NULL without touching `out_len` if it is
/// NULL, and NULL with `*out_len` set to 0 on a null handle.
#[no_mangle]
pub extern "C" fn zerobus_proto_schema_descriptor_bytes(
    schema: *const CZerobusProtoSchema,
    out_len: *mut usize,
) -> *const u8 {
    // The bytes are not null-terminated, so a pointer without a length is
    // unusable. Refuse rather than hand back something the caller can't size.
    if out_len.is_null() {
        return ptr::null();
    }
    // SAFETY: caller upholds the handle contract (valid, unfreed handle).
    let schema_ref = match unsafe { proto_schema_ref(schema) } {
        Ok(s) => s,
        Err(_) => {
            unsafe {
                *out_len = 0;
            }
            return ptr::null();
        }
    };
    unsafe {
        *out_len = schema_ref.descriptor_bytes.len();
    }
    // Valid until the caller's `_free`, which owns the backing allocation.
    schema_ref.descriptor_bytes.as_ptr()
}

/// Encode JSON record to protobuf bytes. Unknown keys are ignored.
///
/// Values follow protobuf's JSON mapping; a few column types need shaping:
/// - DATE/TIMESTAMP/TIMESTAMP_NTZ: integers (days / micros since epoch), not strings.
/// - BINARY: base64-encoded string, not a JSON array of bytes.
/// - DECIMAL: string (e.g. "123.45"), to preserve precision/scale.
/// - VARIANT: a JSON-encoded string (a string whose contents are the variant's JSON).
/// - ARRAY/MAP/STRUCT: JSON array / object / object respectively.
/// - LONG/BIGINT above 2^53: pass as a JSON string, else the value loses
///   precision as a JSON number.
///
/// Presence is enforced only for top-level non-nullable scalar and struct
/// columns (proto2 `required`); a record omitting one fails. Non-nullable
/// ARRAY/MAP columns map to `repeated`, which has no presence, so an omitted one
/// encodes as empty rather than failing; required fields nested inside a STRUCT
/// are likewise not presence-checked.
/// Returns true on success; caller must free buffer with `zerobus_free_proto_bytes`.
/// On failure `*out_data` is set to NULL and `*out_len` to 0.
#[no_mangle]
pub extern "C" fn zerobus_proto_schema_encode_json(
    schema: *const CZerobusProtoSchema,
    record_json: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
    result: *mut CResult,
) -> bool {
    if out_data.is_null() || out_len.is_null() {
        write_error_result(result, "Output pointers are null", false);
        return false;
    }
    // Initialize outputs up front so every failure path leaves them null/0 — a
    // caller that frees on failure then hits a no-op rather than a stale or
    // uninitialized pointer.
    unsafe {
        *out_data = ptr::null_mut();
        *out_len = 0;
    }

    // SAFETY: caller upholds the handle contract — a valid handle not freed for
    // the duration of this call.
    let schema_ref = match unsafe { proto_schema_ref(schema) } {
        Ok(s) => s,
        Err(msg) => {
            write_error_result(result, msg, false);
            return false;
        }
    };
    let json = match unsafe { c_str_to_string(record_json) } {
        Ok(s) => s,
        Err(e) => {
            write_error_result(result, e, false);
            return false;
        }
    };

    let mut deserializer = serde_json::Deserializer::from_str(&json);
    // Records carry extra non-column fields; ignore them rather than erroring.
    let options = DeserializeOptions::new().deny_unknown_fields(false);
    let message = match DynamicMessage::deserialize_with_options(
        schema_ref.message.clone(),
        &mut deserializer,
        &options,
    ) {
        Ok(m) => m,
        Err(e) => {
            write_error_result(result, &format!("failed to encode record: {e}"), false);
            return false;
        }
    };
    if let Err(e) = deserializer.end() {
        write_error_result(
            result,
            &format!("unexpected trailing content in record JSON: {e}"),
            false,
        );
        return false;
    }

    // Top-level non-nullable scalar/struct columns are proto2 `required`, but
    // prost-reflect doesn't enforce presence on encode — reject a missing one
    // here rather than emit wire bytes the server rejects. (ARRAY/MAP are
    // `repeated`, which has no presence, and nested struct fields aren't walked.)
    let missing: Vec<String> = schema_ref
        .message
        .fields()
        .filter(|f| matches!(f.cardinality(), Cardinality::Required) && !message.has_field(f))
        .map(|f| f.name().to_string())
        .collect();
    if !missing.is_empty() {
        write_error_result(
            result,
            &format!("record missing required field(s): {}", missing.join(", ")),
            false,
        );
        return false;
    }

    let bytes = message.encode_to_vec();
    let len = bytes.len();
    // into_boxed_slice() shrinks capacity to len so the matching
    // zerobus_free_proto_bytes reconstruction is sound.
    let data_ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8;
    unsafe {
        *out_data = data_ptr;
        *out_len = len;
    }
    write_success_result(result);
    true
}

/// Free a buffer returned by `zerobus_proto_schema_encode_json`.
#[no_mangle]
pub extern "C" fn zerobus_free_proto_bytes(data: *mut u8, len: usize) {
    // An all-default record encodes to zero bytes: a non-null, zero-length
    // boxed slice. Reconstruct on `!data.is_null()` alone; gating on `len > 0`
    // would leak it.
    if !data.is_null() {
        unsafe {
            // data came from Box::into_raw(bytes.into_boxed_slice()), so
            // capacity == len and this reconstruction is sound (len 0 included).
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(data, len));
        }
    }
}

/// Free a handle from `zerobus_proto_schema_from_uc_json`. Call exactly once,
/// after every other call using this handle has returned. The handle may be
/// shared by concurrent readers (`descriptor_bytes`, `encode_json`), but `free`
/// must not race any of them.
#[no_mangle]
pub extern "C" fn zerobus_proto_schema_free(schema: *mut CZerobusProtoSchema) {
    if !schema.is_null() {
        unsafe {
            // Reclaim the Box handed to C by from_uc_json and drop it.
            let _ = Box::from_raw(schema as *mut ProtoSchema);
        }
    }
}
