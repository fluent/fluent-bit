#[cfg(test)]
mod tests {
    use crate::{
        c_record_type, intern_header_key, validate_sdk_ptr, validate_stream_ptr,
        write_error_result, write_success_result, zerobus_free_error_message,
        zerobus_get_default_config, zerobus_sdk_builder_application_name,
        zerobus_sdk_builder_build, zerobus_sdk_builder_disable_tls, zerobus_sdk_builder_endpoint,
        zerobus_sdk_builder_free, zerobus_sdk_builder_new, zerobus_sdk_builder_sdk_identifier,
        zerobus_sdk_builder_unity_catalog_url, zerobus_sdk_free, CHeaders, CResult,
        CallbackHeadersProvider, RecordType, ZerobusError,
    };
    use databricks_zerobus_ingest_sdk::HeadersProvider;
    use std::ffi::{CStr, CString};
    use std::ptr;

    // Helper for c_str_to_string since it's private
    unsafe fn test_c_str_to_string(
        c_str: *const std::os::raw::c_char,
    ) -> Result<String, &'static str> {
        if c_str.is_null() {
            return Err("Null pointer passed");
        }
        CStr::from_ptr(c_str)
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| "Invalid UTF-8 string")
    }

    // ========================================================================
    // Safety Wrapper Tests
    // ========================================================================

    #[test]
    fn test_validate_sdk_ptr_null() {
        let result = validate_sdk_ptr(ptr::null_mut());
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "SDK pointer is null");
    }

    #[test]
    fn test_validate_stream_ptr_null() {
        let result = validate_stream_ptr(ptr::null_mut());
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Stream pointer is null");
    }

    #[test]
    fn test_write_error_result() {
        let mut result = CResult {
            success: true,
            error_message: ptr::null_mut(),
            is_retryable: false,
        };

        write_error_result(&mut result as *mut CResult, "Test error", true);

        assert!(!result.success);
        assert!(!result.error_message.is_null());
        assert!(result.is_retryable);

        // Clean up
        unsafe {
            if !result.error_message.is_null() {
                let _ = CString::from_raw(result.error_message);
            }
        }
    }

    #[test]
    fn test_write_success_result() {
        let mut result = CResult {
            success: false,
            error_message: CString::new("error").unwrap().into_raw(),
            is_retryable: true,
        };

        write_success_result(&mut result as *mut CResult);

        assert!(result.success);
        assert!(result.error_message.is_null());
        assert!(!result.is_retryable);
    }

    #[test]
    fn test_write_error_result_with_null_pointer() {
        // Should not panic when result pointer is null
        write_error_result(ptr::null_mut(), "Test error", false);
        // If we get here, test passed
    }

    #[test]
    fn test_write_success_result_with_null_pointer() {
        // Should not panic when result pointer is null
        write_success_result(ptr::null_mut());
        // If we get here, test passed
    }

    // ========================================================================
    // Header Key Cache Tests
    // ========================================================================

    #[test]
    fn test_intern_header_key_caches_keys() {
        // First call - should create new entry
        let key1 = intern_header_key("Authorization".to_string());

        // Second call with same string - should return cached entry
        let key2 = intern_header_key("Authorization".to_string());

        // Should be the same pointer (same address in memory)
        assert_eq!(key1.as_ptr(), key2.as_ptr());
    }

    #[test]
    fn test_intern_header_key_different_keys() {
        let key1 = intern_header_key("Authorization".to_string());
        let key2 = intern_header_key("Content-Type".to_string());

        // Different keys should have different pointers
        assert_ne!(key1.as_ptr(), key2.as_ptr());
        assert_eq!(key1, "Authorization");
        assert_eq!(key2, "Content-Type");
    }

    #[test]
    fn test_intern_header_key_prevents_duplicate_leaks() {
        // Clear the cache first (can't actually do this safely in test, but we can verify behavior)
        let initial_key = intern_header_key("X-Test-Header".to_string());

        // Call many times
        for _ in 0..100 {
            let key = intern_header_key("X-Test-Header".to_string());
            // All should point to the same memory location
            assert_eq!(initial_key.as_ptr(), key.as_ptr());
        }
    }

    // ========================================================================
    // CResult Tests
    // ========================================================================

    #[test]
    fn test_cresult_success() {
        let result = CResult::success();
        assert!(result.success);
        assert!(result.error_message.is_null());
        assert!(!result.is_retryable);
    }

    #[test]
    fn test_cresult_error() {
        let error = ZerobusError::InvalidArgument("Test error".to_string());
        let result = CResult::error(error);

        assert!(!result.success);
        assert!(!result.error_message.is_null());

        // Verify error message
        let msg = unsafe { CStr::from_ptr(result.error_message).to_string_lossy() };
        assert!(msg.contains("Test error"));

        // Clean up
        unsafe {
            let _ = CString::from_raw(result.error_message);
        }
    }

    // ========================================================================
    // Configuration Tests
    // ========================================================================

    #[test]
    fn test_c_record_type_mapping() {
        assert_eq!(c_record_type(1), RecordType::Proto);
        assert_eq!(c_record_type(2), RecordType::Json);
        assert_eq!(c_record_type(999), RecordType::Unspecified);
        assert_eq!(c_record_type(0), RecordType::Unspecified);
    }

    // ========================================================================
    // zerobus_sdk_builder Tests
    // ========================================================================

    /// Builds an SDK via the C builder API. Caller frees the SDK and any
    /// error message.
    fn build_via_c_builder(
        endpoint: &str,
        unity_catalog_url: &str,
        sdk_identifier: Option<&str>,
        application_name: Option<&str>,
    ) -> (*mut crate::CZerobusSdk, CResult) {
        let endpoint_c = CString::new(endpoint).unwrap();
        let uc_c = CString::new(unity_catalog_url).unwrap();

        let builder = zerobus_sdk_builder_new();
        assert!(!builder.is_null());

        zerobus_sdk_builder_endpoint(builder, endpoint_c.as_ptr());
        zerobus_sdk_builder_unity_catalog_url(builder, uc_c.as_ptr());

        if let Some(id) = sdk_identifier {
            let id_c = CString::new(id).unwrap();
            zerobus_sdk_builder_sdk_identifier(builder, id_c.as_ptr());
        }
        if let Some(app) = application_name {
            let app_c = CString::new(app).unwrap();
            zerobus_sdk_builder_application_name(builder, app_c.as_ptr());
        }

        let mut result = CResult {
            success: false,
            error_message: ptr::null_mut(),
            is_retryable: false,
        };
        let sdk = zerobus_sdk_builder_build(builder, &mut result);
        (sdk, result)
    }

    #[test]
    fn test_builder_minimal() {
        let (sdk, result) =
            build_via_c_builder("https://workspace.zerobus.databricks.com", "", None, None);
        assert!(result.success, "expected success, got error");
        assert!(!sdk.is_null());
        zerobus_sdk_free(sdk);
    }

    #[test]
    fn test_builder_with_sdk_identifier() {
        let (sdk, result) = build_via_c_builder(
            "https://workspace.zerobus.databricks.com",
            "",
            Some("zerobus-sdk-go/1.3.0"),
            None,
        );
        assert!(result.success);
        assert!(!sdk.is_null());
        zerobus_sdk_free(sdk);
    }

    #[test]
    fn test_builder_with_application_name() {
        let (sdk, result) = build_via_c_builder(
            "https://workspace.zerobus.databricks.com",
            "",
            None,
            Some("my-app/1.0"),
        );
        assert!(result.success);
        assert!(!sdk.is_null());
        zerobus_sdk_free(sdk);
    }

    #[test]
    fn test_builder_both_user_agent_options() {
        let (sdk, result) = build_via_c_builder(
            "https://workspace.zerobus.databricks.com",
            "",
            Some("zerobus-sdk-go/1.3.0"),
            Some("my-app/1.0"),
        );
        assert!(result.success);
        assert!(!sdk.is_null());
        zerobus_sdk_free(sdk);
    }

    #[test]
    fn test_builder_empty_strings_are_noops() {
        // Empty identifier/application_name must not produce a trailing space.
        let (sdk, result) = build_via_c_builder(
            "https://workspace.zerobus.databricks.com",
            "",
            Some(""),
            Some(""),
        );
        assert!(result.success);
        assert!(!sdk.is_null());
        zerobus_sdk_free(sdk);
    }

    #[test]
    fn test_builder_build_consumes_on_error() {
        // Missing endpoint fails build. Builder must still be consumed —
        // don't _free the pointer afterward (use-after-free).
        let builder = zerobus_sdk_builder_new();
        let mut result = CResult {
            success: false,
            error_message: ptr::null_mut(),
            is_retryable: false,
        };
        let sdk = zerobus_sdk_builder_build(builder, &mut result);
        assert!(sdk.is_null());
        assert!(!result.success);
        zerobus_free_error_message(result.error_message);
    }

    #[test]
    fn test_builder_free_without_build() {
        let builder = zerobus_sdk_builder_new();
        zerobus_sdk_builder_free(builder);
    }

    #[test]
    fn test_builder_free_on_null_is_safe() {
        zerobus_sdk_builder_free(ptr::null_mut());
    }

    #[test]
    fn test_builder_setters_on_null_are_safe() {
        let s = CString::new("x").unwrap();
        zerobus_sdk_builder_endpoint(ptr::null_mut(), s.as_ptr());
        zerobus_sdk_builder_unity_catalog_url(ptr::null_mut(), s.as_ptr());
        zerobus_sdk_builder_sdk_identifier(ptr::null_mut(), s.as_ptr());
        zerobus_sdk_builder_application_name(ptr::null_mut(), s.as_ptr());
        zerobus_sdk_builder_disable_tls(ptr::null_mut());
    }

    #[test]
    fn test_builder_disable_tls_for_plain_http() {
        let endpoint_c = CString::new("http://localhost:50051").unwrap();
        let builder = zerobus_sdk_builder_new();
        zerobus_sdk_builder_endpoint(builder, endpoint_c.as_ptr());
        zerobus_sdk_builder_disable_tls(builder);
        let mut result = CResult {
            success: false,
            error_message: ptr::null_mut(),
            is_retryable: false,
        };
        let sdk = zerobus_sdk_builder_build(builder, &mut result);
        assert!(result.success);
        assert!(!sdk.is_null());
        zerobus_sdk_free(sdk);
    }

    #[test]
    fn test_get_default_config() {
        let config = zerobus_get_default_config();

        // Verify it returns reasonable defaults
        assert!(config.max_inflight_requests > 0);
        assert_eq!(config.record_type, 1); // Proto
    }

    // ========================================================================
    // C String Conversion Tests
    // ========================================================================

    #[test]
    fn test_c_str_to_string_valid() {
        let test_str = CString::new("Hello, World!").unwrap();
        let result = unsafe { test_c_str_to_string(test_str.as_ptr()) };

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello, World!");
    }

    #[test]
    fn test_c_str_to_string_null() {
        let result = unsafe { test_c_str_to_string(ptr::null()) };
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Null pointer passed");
    }

    #[test]
    fn test_c_str_to_string_empty() {
        let test_str = CString::new("").unwrap();
        let result = unsafe { test_c_str_to_string(test_str.as_ptr()) };

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    // ========================================================================
    // Memory Management Tests
    // ========================================================================

    #[test]
    fn test_zerobus_free_error_message_null() {
        // Should not panic with null pointer
        zerobus_free_error_message(ptr::null_mut());
    }

    #[test]
    fn test_zerobus_free_error_message_valid() {
        let msg = CString::new("Test error").unwrap().into_raw();
        zerobus_free_error_message(msg);
        // If we get here without crashing, test passed
    }

    // ========================================================================
    // Thread Safety Tests
    // ========================================================================

    #[test]
    fn test_callback_headers_provider_sequential() {
        extern "C" fn test_callback(_user_data: *mut std::ffi::c_void) -> CHeaders {
            CHeaders {
                headers: ptr::null_mut(),
                count: 0,
                error_message: ptr::null_mut(),
            }
        }

        let provider = CallbackHeadersProvider::new(test_callback, ptr::null_mut());

        // Sequential calls should work fine
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result1 = rt.block_on(provider.get_headers());
        assert!(result1.is_ok());

        let result2 = rt.block_on(provider.get_headers());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_callback_headers_provider_returns_headers() {
        extern "C" fn test_callback(_user_data: *mut std::ffi::c_void) -> CHeaders {
            // Create simple test headers
            let auth_key = CString::new("Authorization").unwrap().into_raw();
            let auth_val = CString::new("Bearer test-token").unwrap().into_raw();

            let header = Box::new(crate::CHeader {
                key: auth_key,
                value: auth_val,
            });

            CHeaders {
                headers: Box::into_raw(header),
                count: 1,
                error_message: ptr::null_mut(),
            }
        }

        let provider = CallbackHeadersProvider::new(test_callback, ptr::null_mut());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(provider.get_headers());

        assert!(result.is_ok());
        let headers = result.unwrap();
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("Authorization"));
    }

    // ========================================================================
    // Dynamic protobuf schema tests
    // ========================================================================

    use crate::{
        zerobus_free_proto_bytes, zerobus_proto_schema_descriptor_bytes,
        zerobus_proto_schema_encode_json, zerobus_proto_schema_free,
        zerobus_proto_schema_from_uc_json,
    };
    use prost::Message;
    use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};

    // Minimal Unity Catalog table-metadata JSON, shaped like the body of
    // GET /api/2.1/unity-catalog/tables/{name}.
    fn sample_uc_table_json() -> CString {
        let json = r#"{
            "name": "events",
            "catalog_name": "main",
            "schema_name": "analytics",
            "columns": [
                {"name": "id", "type_name": "BIGINT", "type_text": "bigint", "nullable": false, "position": 0},
                {"name": "payload", "type_name": "STRING", "type_text": "string", "nullable": true, "position": 1},
                {"name": "ts", "type_name": "TIMESTAMP", "type_text": "timestamp", "nullable": true, "position": 2}
            ]
        }"#;
        CString::new(json).unwrap()
    }

    // A CResult to be written into by the function under test. Starts as a
    // failure so a success-path test proves the call flipped it to success.
    fn unwritten_result() -> CResult {
        CResult {
            success: false,
            error_message: ptr::null_mut(),
            is_retryable: false,
        }
    }

    // As above but starts successful, so an error-path test proves the call
    // flipped it to failure.
    fn presumed_success_result() -> CResult {
        CResult {
            success: true,
            error_message: ptr::null_mut(),
            is_retryable: false,
        }
    }

    // Rebuild a MessageDescriptor from the bare DescriptorProto bytes the handle
    // exposes, so a test can decode encoded records back and assert field values
    // — proving the descriptor given to the server and the encoder agree.
    fn message_descriptor_from_bytes(descriptor_bytes: &[u8]) -> MessageDescriptor {
        let descriptor = prost_types::DescriptorProto::decode(descriptor_bytes).unwrap();
        let name = descriptor.name().to_string();
        let file = prost_types::FileDescriptorProto {
            name: Some("test.proto".to_string()),
            message_type: vec![descriptor],
            ..Default::default()
        };
        let mut pool = DescriptorPool::new();
        pool.add_file_descriptor_proto(file).unwrap();
        pool.get_message_by_name(&name).unwrap()
    }

    #[test]
    fn test_proto_schema_from_uc_json_roundtrip() {
        let json = sample_uc_table_json();
        let mut result = unwritten_result();
        let schema = zerobus_proto_schema_from_uc_json(json.as_ptr(), &mut result as *mut CResult);
        assert!(!schema.is_null(), "schema build failed");
        assert!(result.success);

        // Descriptor bytes must decode to the bare DescriptorProto that the
        // server is given via zerobus_sdk_create_stream.
        let mut dlen: usize = 0;
        let dptr = zerobus_proto_schema_descriptor_bytes(schema, &mut dlen as *mut usize);
        assert!(!dptr.is_null());
        assert!(dlen > 0);
        let desc_bytes = unsafe { std::slice::from_raw_parts(dptr, dlen) };
        let descriptor = prost_types::DescriptorProto::decode(desc_bytes).unwrap();
        // schema_name + table_name, sanitized to PascalCase.
        assert_eq!(descriptor.name(), "AnalyticsEvents");
        assert_eq!(descriptor.field.len(), 3);

        // Encode a record; unknown keys are ignored, timestamps are integers.
        let record =
            CString::new(r#"{"id": 7, "payload": "hello", "ts": 1700000000000000, "extra": "x"}"#)
                .unwrap();
        let mut out_data: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let mut enc_result = unwritten_result();
        let ok = zerobus_proto_schema_encode_json(
            schema,
            record.as_ptr(),
            &mut out_data as *mut *mut u8,
            &mut out_len as *mut usize,
            &mut enc_result as *mut CResult,
        );
        assert!(ok, "encode failed");
        assert!(enc_result.success);
        assert!(!out_data.is_null());
        assert!(out_len > 0);

        // Decode the encoded bytes against the same descriptor and assert the
        // values round-trip: the encoding is correct, not merely non-empty.
        let encoded = unsafe { std::slice::from_raw_parts(out_data, out_len) };
        let msg_desc = message_descriptor_from_bytes(desc_bytes);
        let decoded = DynamicMessage::decode(msg_desc, encoded).unwrap();
        assert_eq!(decoded.get_field_by_name("id").unwrap().as_i64(), Some(7));
        assert_eq!(
            decoded.get_field_by_name("payload").unwrap().as_str(),
            Some("hello")
        );
        assert_eq!(
            decoded.get_field_by_name("ts").unwrap().as_i64(),
            Some(1700000000000000)
        );

        zerobus_free_proto_bytes(out_data, out_len);
        zerobus_proto_schema_free(schema);
    }

    #[test]
    fn test_proto_schema_from_uc_json_invalid_json_errors() {
        let bad = CString::new("not json").unwrap();
        let mut result = presumed_success_result();
        let schema = zerobus_proto_schema_from_uc_json(bad.as_ptr(), &mut result as *mut CResult);
        assert!(schema.is_null());
        assert!(!result.success);
        // A parse failure is a caller error, not a transient one. Assert on the
        // error code rather than the message text, which is free to change.
        assert!(!result.is_retryable);
        assert!(!result.error_message.is_null());
        zerobus_free_error_message(result.error_message);
    }

    #[test]
    fn test_proto_schema_from_uc_json_unsupported_type_errors() {
        // Parses cleanly into UcTableSchema but carries a column type the
        // descriptor builder rejects — exercises the schema-conversion error
        // path, distinct from a JSON parse failure.
        let json = CString::new(
            r#"{
                "name": "t", "catalog_name": "c", "schema_name": "s",
                "columns": [
                    {"name": "x", "type_name": "GEOGRAPHY", "type_text": "geography", "nullable": true, "position": 0}
                ]
            }"#,
        )
        .unwrap();
        let mut result = presumed_success_result();
        let schema = zerobus_proto_schema_from_uc_json(json.as_ptr(), &mut result as *mut CResult);
        assert!(schema.is_null());
        assert!(!result.success);
        assert!(!result.error_message.is_null());
        zerobus_free_error_message(result.error_message);
    }

    #[test]
    fn test_proto_schema_from_uc_json_null_input_errors() {
        let mut result = presumed_success_result();
        let schema = zerobus_proto_schema_from_uc_json(ptr::null(), &mut result as *mut CResult);
        assert!(schema.is_null());
        assert!(!result.success);
        zerobus_free_error_message(result.error_message);
    }

    #[test]
    fn test_proto_schema_descriptor_bytes_null_handle() {
        // A null handle must yield a null pointer and zero the out-length so the
        // caller never reads a stale length.
        let mut len: usize = 123;
        let dptr = zerobus_proto_schema_descriptor_bytes(ptr::null(), &mut len as *mut usize);
        assert!(dptr.is_null());
        assert_eq!(len, 0);
    }

    #[test]
    fn test_proto_schema_descriptor_bytes_null_out_len() {
        // The descriptor bytes are not null-terminated, so a null out_len leaves
        // the caller no way to size them. A valid handle must still yield a null
        // pointer rather than a length-less buffer.
        let json = sample_uc_table_json();
        let mut build = unwritten_result();
        let schema = zerobus_proto_schema_from_uc_json(json.as_ptr(), &mut build as *mut CResult);
        assert!(!schema.is_null(), "schema build failed");

        let dptr = zerobus_proto_schema_descriptor_bytes(schema, ptr::null_mut());
        assert!(dptr.is_null());

        zerobus_proto_schema_free(schema);
    }

    #[test]
    fn test_proto_schema_encode_null_schema_errors() {
        let record = CString::new(r#"{"id": 1}"#).unwrap();
        // Seed the outputs with non-null/non-zero sentinels: a failed call must
        // clear them so a caller that frees on error hits a no-op. The schema
        // check fails before any encoding, exercising the earliest failure path.
        let mut sentinel: u8 = 0;
        let mut out_data: *mut u8 = &mut sentinel as *mut u8;
        let mut out_len: usize = 999;
        let mut result = presumed_success_result();
        let ok = zerobus_proto_schema_encode_json(
            ptr::null(),
            record.as_ptr(),
            &mut out_data as *mut *mut u8,
            &mut out_len as *mut usize,
            &mut result as *mut CResult,
        );
        assert!(!ok);
        assert!(!result.success);
        assert!(out_data.is_null(), "outputs must be cleared on failure");
        assert_eq!(out_len, 0, "outputs must be cleared on failure");
        zerobus_free_error_message(result.error_message);
    }

    #[test]
    fn test_proto_schema_encode_malformed_record_errors() {
        let json = sample_uc_table_json();
        let mut build = unwritten_result();
        let schema = zerobus_proto_schema_from_uc_json(json.as_ptr(), &mut build as *mut CResult);
        assert!(!schema.is_null());

        let bad_record = CString::new("{ not valid json").unwrap();
        let mut out_data: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let mut enc_result = presumed_success_result();
        let ok = zerobus_proto_schema_encode_json(
            schema,
            bad_record.as_ptr(),
            &mut out_data as *mut *mut u8,
            &mut out_len as *mut usize,
            &mut enc_result as *mut CResult,
        );
        assert!(!ok);
        assert!(!enc_result.success);
        assert!(!enc_result.error_message.is_null());
        assert!(out_data.is_null(), "no buffer should be allocated on error");
        assert_eq!(out_len, 0, "length must be cleared on error");
        zerobus_free_error_message(enc_result.error_message);
        zerobus_proto_schema_free(schema);
    }

    #[test]
    fn test_proto_schema_encode_null_out_pointers_errors() {
        let json = sample_uc_table_json();
        let mut build = unwritten_result();
        let schema = zerobus_proto_schema_from_uc_json(json.as_ptr(), &mut build as *mut CResult);
        assert!(!schema.is_null());

        let record = CString::new(r#"{"id": 1}"#).unwrap();
        let mut enc_result = presumed_success_result();
        let ok = zerobus_proto_schema_encode_json(
            schema,
            record.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut enc_result as *mut CResult,
        );
        assert!(!ok);
        assert!(!enc_result.success);
        zerobus_free_error_message(enc_result.error_message);
        zerobus_proto_schema_free(schema);
    }

    #[test]
    fn test_proto_schema_encode_missing_required_field_errors() {
        // `id` is non-nullable (proto2 `required`); a record omitting it must be
        // rejected rather than encoded.
        let json = sample_uc_table_json();
        let mut build = unwritten_result();
        let schema = zerobus_proto_schema_from_uc_json(json.as_ptr(), &mut build as *mut CResult);
        assert!(!schema.is_null());

        let record = CString::new(r#"{"payload": "hello"}"#).unwrap();
        let mut out_data: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let mut enc_result = presumed_success_result();
        let ok = zerobus_proto_schema_encode_json(
            schema,
            record.as_ptr(),
            &mut out_data as *mut *mut u8,
            &mut out_len as *mut usize,
            &mut enc_result as *mut CResult,
        );
        assert!(!ok);
        assert!(!enc_result.success);
        // A missing required field is a caller error, not a transient one. Assert
        // on the error code rather than the message text, which is free to change.
        assert!(!enc_result.is_retryable);
        assert!(!enc_result.error_message.is_null());
        assert!(out_data.is_null(), "no buffer should be allocated on error");
        assert_eq!(out_len, 0, "length must be cleared on error");
        zerobus_free_error_message(enc_result.error_message);
        zerobus_proto_schema_free(schema);
    }

    // UC table JSON for the type-contract tests: a required key plus one column
    // of the type under test.
    fn uc_table_json_with_column(col_name: &str, type_name: &str) -> CString {
        let json = format!(
            r#"{{
                "name": "t", "catalog_name": "c", "schema_name": "s",
                "columns": [
                    {{"name": "k", "type_name": "BIGINT", "type_text": "bigint", "nullable": false, "position": 0}},
                    {{"name": "{col_name}", "type_name": "{type_name}", "type_text": "{type_name}", "nullable": true, "position": 1}}
                ]
            }}"#
        );
        CString::new(json).unwrap()
    }

    // Build a schema + encode one record, returning the decoded message so a test
    // can assert how a given JSON value lands on the wire.
    fn encode_and_decode(table_json: &CString, record_json: &str) -> DynamicMessage {
        let mut build = unwritten_result();
        let schema =
            zerobus_proto_schema_from_uc_json(table_json.as_ptr(), &mut build as *mut CResult);
        assert!(!schema.is_null(), "schema build failed");

        let mut dlen: usize = 0;
        let dptr = zerobus_proto_schema_descriptor_bytes(schema, &mut dlen as *mut usize);
        let desc_bytes = unsafe { std::slice::from_raw_parts(dptr, dlen) };
        let msg_desc = message_descriptor_from_bytes(desc_bytes);

        let record = CString::new(record_json).unwrap();
        let mut out_data: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let mut enc_result = unwritten_result();
        let ok = zerobus_proto_schema_encode_json(
            schema,
            record.as_ptr(),
            &mut out_data as *mut *mut u8,
            &mut out_len as *mut usize,
            &mut enc_result as *mut CResult,
        );
        assert!(ok, "encode failed");
        let encoded = unsafe { std::slice::from_raw_parts(out_data, out_len) };
        let decoded = DynamicMessage::decode(msg_desc, encoded).unwrap();

        zerobus_free_proto_bytes(out_data, out_len);
        zerobus_proto_schema_free(schema);
        decoded
    }

    #[test]
    fn test_proto_schema_encode_binary_is_base64_string() {
        // BINARY maps to proto `bytes`; prost-reflect's serde layer accepts it
        // only as a base64-encoded string (not a JSON array of byte values).
        let table = uc_table_json_with_column("blob", "BINARY");
        // "aGVsbG8=" is base64 for "hello".
        let decoded = encode_and_decode(&table, r#"{"k": 1, "blob": "aGVsbG8="}"#);
        assert_eq!(
            decoded
                .get_field_by_name("blob")
                .unwrap()
                .as_bytes()
                .map(|b| b.as_ref()),
            Some(b"hello".as_slice())
        );
    }

    #[test]
    fn test_proto_schema_encode_decimal_is_string() {
        // DECIMAL maps to proto `string`; the value must be passed as a JSON
        // string to preserve precision and scale.
        let table = uc_table_json_with_column("price", "DECIMAL");
        let decoded = encode_and_decode(&table, r#"{"k": 1, "price": "123.45"}"#);
        assert_eq!(
            decoded.get_field_by_name("price").unwrap().as_str(),
            Some("123.45")
        );
    }

    #[test]
    fn test_proto_schema_encode_large_int64_as_string_preserves_precision() {
        // int64 above 2^53 loses precision as a JSON number; passing it as a
        // string round-trips exactly.
        let table = uc_table_json_with_column("big", "BIGINT");
        let decoded = encode_and_decode(&table, r#"{"k": 1, "big": "9223372036854775807"}"#);
        assert_eq!(
            decoded.get_field_by_name("big").unwrap().as_i64(),
            Some(9223372036854775807)
        );
    }

    #[test]
    fn test_proto_schema_encode_variant_is_json_encoded_string() {
        // VARIANT maps to proto `string`; the value is a JSON-encoded string
        // (a string whose contents are the variant's JSON).
        let table = uc_table_json_with_column("v", "VARIANT");
        let decoded = encode_and_decode(&table, r#"{"k": 1, "v": "{\"a\":1,\"b\":[2,3]}"}"#);
        assert_eq!(
            decoded.get_field_by_name("v").unwrap().as_str(),
            Some(r#"{"a":1,"b":[2,3]}"#)
        );
    }

    #[test]
    fn test_proto_schema_encode_array_is_json_array() {
        // ARRAY<T> maps to `repeated T`; the value is a JSON array. Complex
        // columns carry their shape in `type_json`, so build the table directly.
        let table = CString::new(
            r#"{
                "name": "t", "catalog_name": "c", "schema_name": "s",
                "columns": [
                    {"name": "k", "type_name": "BIGINT", "type_text": "bigint", "nullable": false, "position": 0},
                    {"name": "tags", "type_name": "ARRAY", "type_text": "array<int>", "nullable": true, "position": 1,
                     "type_json": "{\"type\":\"array\",\"elementType\":\"integer\",\"containsNull\":false}"}
                ]
            }"#,
        )
        .unwrap();
        let decoded = encode_and_decode(&table, r#"{"k": 1, "tags": [10, 20, 30]}"#);
        let list = decoded.get_field_by_name("tags").unwrap();
        let values: Vec<i64> = list
            .as_list()
            .unwrap()
            .iter()
            .map(|v| v.as_i32().unwrap() as i64)
            .collect();
        assert_eq!(values, vec![10, 20, 30]);
    }

    #[test]
    fn test_proto_schema_encode_map_roundtrip() {
        // MAP<K,V> maps to a synthetic map-entry message + `repeated`; the value
        // is a JSON object. Protobuf-JSON map keys are always strings on the wire.
        let table = CString::new(
            r#"{
                "name": "t", "catalog_name": "c", "schema_name": "s",
                "columns": [
                    {"name": "k", "type_name": "BIGINT", "type_text": "bigint", "nullable": false, "position": 0},
                    {"name": "attrs", "type_name": "MAP", "type_text": "map<string,int>", "nullable": true, "position": 1,
                     "type_json": "{\"type\":\"map\",\"keyType\":\"string\",\"valueType\":\"integer\",\"valueContainsNull\":false}"}
                ]
            }"#,
        )
        .unwrap();
        let decoded = encode_and_decode(&table, r#"{"k": 1, "attrs": {"a": 1, "b": 2}}"#);
        let field = decoded.get_field_by_name("attrs").unwrap();
        let map = field.as_map().unwrap();
        let mut pairs: Vec<(String, i32)> = map
            .iter()
            .map(|(k, v)| (k.as_str().unwrap().to_string(), v.as_i32().unwrap()))
            .collect();
        pairs.sort();
        assert_eq!(pairs, vec![("a".to_string(), 1), ("b".to_string(), 2)]);
    }

    #[test]
    fn test_proto_schema_encode_struct_roundtrip() {
        // STRUCT<...> maps to a nested message; the value is a JSON object.
        let table = CString::new(
            r#"{
                "name": "t", "catalog_name": "c", "schema_name": "s",
                "columns": [
                    {"name": "k", "type_name": "BIGINT", "type_text": "bigint", "nullable": false, "position": 0},
                    {"name": "addr", "type_name": "STRUCT", "type_text": "struct<city:string,zip:int>", "nullable": true, "position": 1,
                     "type_json": "{\"type\":\"struct\",\"fields\":[{\"name\":\"city\",\"type\":\"string\",\"nullable\":true,\"metadata\":{}},{\"name\":\"zip\",\"type\":\"integer\",\"nullable\":true,\"metadata\":{}}]}"}
                ]
            }"#,
        )
        .unwrap();
        let decoded =
            encode_and_decode(&table, r#"{"k": 1, "addr": {"city": "NYC", "zip": 10001}}"#);
        let field = decoded.get_field_by_name("addr").unwrap();
        let addr = field.as_message().unwrap();
        assert_eq!(
            addr.get_field_by_name("city").unwrap().as_str(),
            Some("NYC")
        );
        assert_eq!(addr.get_field_by_name("zip").unwrap().as_i32(), Some(10001));
    }

    #[test]
    fn test_proto_schema_encode_array_of_struct_roundtrip() {
        // ARRAY<STRUCT<...>> maps to `repeated <nested message>`; the value is a
        // JSON array of objects.
        let table = CString::new(
            r#"{
                "name": "t", "catalog_name": "c", "schema_name": "s",
                "columns": [
                    {"name": "k", "type_name": "BIGINT", "type_text": "bigint", "nullable": false, "position": 0},
                    {"name": "items", "type_name": "ARRAY", "type_text": "array<struct<id:int>>", "nullable": true, "position": 1,
                     "type_json": "{\"type\":\"array\",\"elementType\":{\"type\":\"struct\",\"fields\":[{\"name\":\"id\",\"type\":\"integer\",\"nullable\":true,\"metadata\":{}}]},\"containsNull\":false}"}
                ]
            }"#,
        )
        .unwrap();
        let decoded = encode_and_decode(&table, r#"{"k": 1, "items": [{"id": 1}, {"id": 2}]}"#);
        let field = decoded.get_field_by_name("items").unwrap();
        let ids: Vec<i32> = field
            .as_list()
            .unwrap()
            .iter()
            .map(|v| {
                v.as_message()
                    .unwrap()
                    .get_field_by_name("id")
                    .unwrap()
                    .as_i32()
                    .unwrap()
            })
            .collect();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn test_proto_schema_encode_date_is_days_since_epoch() {
        // DATE maps to proto `int32`; the value is days since the Unix epoch, an
        // integer (not an ISO-8601 string). 19000 days ≈ 2022-01-08.
        let table = uc_table_json_with_column("d", "DATE");
        let decoded = encode_and_decode(&table, r#"{"k": 1, "d": 19000}"#);
        assert_eq!(
            decoded.get_field_by_name("d").unwrap().as_i32(),
            Some(19000)
        );
    }

    #[test]
    fn test_proto_schema_encode_timestamp_ntz_is_micros() {
        // TIMESTAMP_NTZ maps to proto `int64` (same wire shape as TIMESTAMP); the
        // value is microseconds since the epoch, an integer.
        let table = uc_table_json_with_column("tsn", "TIMESTAMP_NTZ");
        let decoded = encode_and_decode(&table, r#"{"k": 1, "tsn": 1700000000000000}"#);
        assert_eq!(
            decoded.get_field_by_name("tsn").unwrap().as_i64(),
            Some(1700000000000000)
        );
    }

    #[test]
    fn test_free_proto_bytes_handles_empty_encoding() {
        // A record with no fields set encodes to zero bytes: out_len == 0 but
        // out_data is a non-null, zero-length boxed slice. Freeing it must
        // reclaim that allocation, not leak it.
        let table = CString::new(
            r#"{
                "name": "t", "catalog_name": "c", "schema_name": "s",
                "columns": [
                    {"name": "opt", "type_name": "INT", "type_text": "int", "nullable": true, "position": 0}
                ]
            }"#,
        )
        .unwrap();
        let mut build = unwritten_result();
        let schema = zerobus_proto_schema_from_uc_json(table.as_ptr(), &mut build as *mut CResult);
        assert!(!schema.is_null(), "schema build failed");

        let record = CString::new(r#"{}"#).unwrap();
        let mut out_data: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let mut enc_result = unwritten_result();
        let ok = zerobus_proto_schema_encode_json(
            schema,
            record.as_ptr(),
            &mut out_data as *mut *mut u8,
            &mut out_len as *mut usize,
            &mut enc_result as *mut CResult,
        );
        assert!(ok, "encode failed");
        assert_eq!(
            out_len, 0,
            "record with no fields set should encode to zero bytes"
        );
        assert!(
            !out_data.is_null(),
            "buffer pointer should be non-null even when empty"
        );

        // The assertion is the absence of a leak/crash on free.
        zerobus_free_proto_bytes(out_data, out_len);
        zerobus_proto_schema_free(schema);
    }

    #[test]
    fn test_proto_schema_shared_across_threads() {
        // The handle may be shared by concurrent readers: many threads encode
        // through one handle at once. `free` is ordered after every worker has
        // joined, so it never races an in-flight encode.
        use std::thread;

        let json = sample_uc_table_json();
        let mut build = unwritten_result();
        let schema = zerobus_proto_schema_from_uc_json(json.as_ptr(), &mut build as *mut CResult);
        assert!(!schema.is_null(), "schema build failed");

        // Raw pointers aren't Send; pass the address as a usize and rebuild it
        // per thread. Safe: threads only read, and the handle outlives them.
        let handle_addr = schema as usize;
        let mut workers = Vec::new();
        for t in 0..8 {
            workers.push(thread::spawn(move || {
                let handle = handle_addr as *const crate::CZerobusProtoSchema;
                for i in 0..200 {
                    let record = CString::new(format!(
                        r#"{{"id": {}, "payload": "p{}"}}"#,
                        t * 1000 + i,
                        i
                    ))
                    .unwrap();
                    let mut out_data: *mut u8 = ptr::null_mut();
                    let mut out_len: usize = 0;
                    let mut enc = unwritten_result();
                    let ok = zerobus_proto_schema_encode_json(
                        handle,
                        record.as_ptr(),
                        &mut out_data as *mut *mut u8,
                        &mut out_len as *mut usize,
                        &mut enc as *mut CResult,
                    );
                    assert!(ok, "concurrent encode failed");
                    zerobus_free_proto_bytes(out_data, out_len);
                }
            }));
        }
        for w in workers {
            w.join().unwrap();
        }
        zerobus_proto_schema_free(schema);
    }
}
