/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
/* include test cases' include files here */
#include "nghttp2_pq_test.h"
#include "nghttp2_map_test.h"
#include "nghttp2_queue_test.h"
#include "nghttp2_session_test.h"
#include "nghttp2_frame_test.h"
#include "nghttp2_stream_test.h"
#include "nghttp2_hd_test.h"
#include "nghttp2_npn_test.h"
#include "nghttp2_helper_test.h"
#include "nghttp2_buf_test.h"
#include "nghttp2_http_test.h"
#include "nghttp2_extpri_test.h"
#include "nghttp2_ratelim_test.h"

extern int nghttp2_enable_strict_preface;

static int init_suite1(void) { return 0; }

static int clean_suite1(void) { return 0; }

int main(void) {
  CU_pSuite pSuite = NULL;
  unsigned int num_tests_failed;

  nghttp2_enable_strict_preface = 0;

  /* initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry())
    return (int)CU_get_error();

  /* add a suite to the registry */
  pSuite = CU_add_suite("libnghttp2_TestSuite", init_suite1, clean_suite1);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return (int)CU_get_error();
  }

  /* add the tests to the suite */
  if (!CU_add_test(pSuite, "pq", test_nghttp2_pq) ||
      !CU_add_test(pSuite, "pq_update", test_nghttp2_pq_update) ||
      !CU_add_test(pSuite, "pq_remove", test_nghttp2_pq_remove) ||
      !CU_add_test(pSuite, "map", test_nghttp2_map) ||
      !CU_add_test(pSuite, "map_functional", test_nghttp2_map_functional) ||
      !CU_add_test(pSuite, "map_each_free", test_nghttp2_map_each_free) ||
      !CU_add_test(pSuite, "queue", test_nghttp2_queue) ||
      !CU_add_test(pSuite, "npn", test_nghttp2_npn) ||
      !CU_add_test(pSuite, "session_recv", test_nghttp2_session_recv) ||
      !CU_add_test(pSuite, "session_recv_invalid_stream_id",
                   test_nghttp2_session_recv_invalid_stream_id) ||
      !CU_add_test(pSuite, "session_recv_invalid_frame",
                   test_nghttp2_session_recv_invalid_frame) ||
      !CU_add_test(pSuite, "session_recv_eof", test_nghttp2_session_recv_eof) ||
      !CU_add_test(pSuite, "session_recv_data",
                   test_nghttp2_session_recv_data) ||
      !CU_add_test(pSuite, "session_recv_data_no_auto_flow_control",
                   test_nghttp2_session_recv_data_no_auto_flow_control) ||
      !CU_add_test(pSuite, "session_recv_continuation",
                   test_nghttp2_session_recv_continuation) ||
      !CU_add_test(pSuite, "session_recv_headers_with_priority",
                   test_nghttp2_session_recv_headers_with_priority) ||
      !CU_add_test(pSuite, "session_recv_headers_with_padding",
                   test_nghttp2_session_recv_headers_with_padding) ||
      !CU_add_test(pSuite, "session_recv_headers_early_response",
                   test_nghttp2_session_recv_headers_early_response) ||
      !CU_add_test(pSuite, "session_recv_headers_for_closed_stream",
                   test_nghttp2_session_recv_headers_for_closed_stream) ||
      !CU_add_test(pSuite, "session_recv_headers_with_extpri",
                   test_nghttp2_session_recv_headers_with_extpri) ||
      !CU_add_test(pSuite, "session_server_recv_push_response",
                   test_nghttp2_session_server_recv_push_response) ||
      !CU_add_test(pSuite, "session_recv_premature_headers",
                   test_nghttp2_session_recv_premature_headers) ||
      !CU_add_test(pSuite, "session_recv_unknown_frame",
                   test_nghttp2_session_recv_unknown_frame) ||
      !CU_add_test(pSuite, "session_recv_unexpected_continuation",
                   test_nghttp2_session_recv_unexpected_continuation) ||
      !CU_add_test(pSuite, "session_recv_settings_header_table_size",
                   test_nghttp2_session_recv_settings_header_table_size) ||
      !CU_add_test(pSuite, "session_recv_too_large_frame_length",
                   test_nghttp2_session_recv_too_large_frame_length) ||
      !CU_add_test(pSuite, "session_recv_extension",
                   test_nghttp2_session_recv_extension) ||
      !CU_add_test(pSuite, "session_recv_altsvc",
                   test_nghttp2_session_recv_altsvc) ||
      !CU_add_test(pSuite, "session_recv_origin",
                   test_nghttp2_session_recv_origin) ||
      !CU_add_test(pSuite, "session_recv_priority_update",
                   test_nghttp2_session_recv_priority_update) ||
      !CU_add_test(pSuite, "session_continue", test_nghttp2_session_continue) ||
      !CU_add_test(pSuite, "session_add_frame",
                   test_nghttp2_session_add_frame) ||
      !CU_add_test(pSuite, "session_on_request_headers_received",
                   test_nghttp2_session_on_request_headers_received) ||
      !CU_add_test(pSuite, "session_on_response_headers_received",
                   test_nghttp2_session_on_response_headers_received) ||
      !CU_add_test(pSuite, "session_on_headers_received",
                   test_nghttp2_session_on_headers_received) ||
      !CU_add_test(pSuite, "session_on_push_response_headers_received",
                   test_nghttp2_session_on_push_response_headers_received) ||
      !CU_add_test(pSuite, "session_on_priority_received",
                   test_nghttp2_session_on_priority_received) ||
      !CU_add_test(pSuite, "session_on_rst_stream_received",
                   test_nghttp2_session_on_rst_stream_received) ||
      !CU_add_test(pSuite, "session_on_settings_received",
                   test_nghttp2_session_on_settings_received) ||
      !CU_add_test(pSuite, "session_on_push_promise_received",
                   test_nghttp2_session_on_push_promise_received) ||
      !CU_add_test(pSuite, "session_on_ping_received",
                   test_nghttp2_session_on_ping_received) ||
      !CU_add_test(pSuite, "session_on_goaway_received",
                   test_nghttp2_session_on_goaway_received) ||
      !CU_add_test(pSuite, "session_on_window_update_received",
                   test_nghttp2_session_on_window_update_received) ||
      !CU_add_test(pSuite, "session_on_data_received",
                   test_nghttp2_session_on_data_received) ||
      !CU_add_test(pSuite, "session_on_data_received_fail_fast",
                   test_nghttp2_session_on_data_received_fail_fast) ||
      !CU_add_test(pSuite, "session_on_altsvc_received",
                   test_nghttp2_session_on_altsvc_received) ||
      !CU_add_test(pSuite, "session_send_headers_start_stream",
                   test_nghttp2_session_send_headers_start_stream) ||
      !CU_add_test(pSuite, "session_send_headers_reply",
                   test_nghttp2_session_send_headers_reply) ||
      !CU_add_test(pSuite, "session_send_headers_frame_size_error",
                   test_nghttp2_session_send_headers_frame_size_error) ||
      !CU_add_test(pSuite, "session_send_headers_push_reply",
                   test_nghttp2_session_send_headers_push_reply) ||
      !CU_add_test(pSuite, "session_send_rst_stream",
                   test_nghttp2_session_send_rst_stream) ||
      !CU_add_test(pSuite, "session_send_push_promise",
                   test_nghttp2_session_send_push_promise) ||
      !CU_add_test(pSuite, "session_is_my_stream_id",
                   test_nghttp2_session_is_my_stream_id) ||
      !CU_add_test(pSuite, "session_upgrade2", test_nghttp2_session_upgrade2) ||
      !CU_add_test(pSuite, "session_reprioritize_stream",
                   test_nghttp2_session_reprioritize_stream) ||
      !CU_add_test(
          pSuite, "session_reprioritize_stream_with_idle_stream_dep",
          test_nghttp2_session_reprioritize_stream_with_idle_stream_dep) ||
      !CU_add_test(pSuite, "submit_data", test_nghttp2_submit_data) ||
      !CU_add_test(pSuite, "submit_data_read_length_too_large",
                   test_nghttp2_submit_data_read_length_too_large) ||
      !CU_add_test(pSuite, "submit_data_read_length_smallest",
                   test_nghttp2_submit_data_read_length_smallest) ||
      !CU_add_test(pSuite, "submit_data_twice",
                   test_nghttp2_submit_data_twice) ||
      !CU_add_test(pSuite, "submit_request_with_data",
                   test_nghttp2_submit_request_with_data) ||
      !CU_add_test(pSuite, "submit_request_without_data",
                   test_nghttp2_submit_request_without_data) ||
      !CU_add_test(pSuite, "submit_response_with_data",
                   test_nghttp2_submit_response_with_data) ||
      !CU_add_test(pSuite, "submit_response_without_data",
                   test_nghttp2_submit_response_without_data) ||
      !CU_add_test(pSuite, "Submit_response_push_response",
                   test_nghttp2_submit_response_push_response) ||
      !CU_add_test(pSuite, "submit_trailer", test_nghttp2_submit_trailer) ||
      !CU_add_test(pSuite, "submit_headers_start_stream",
                   test_nghttp2_submit_headers_start_stream) ||
      !CU_add_test(pSuite, "submit_headers_reply",
                   test_nghttp2_submit_headers_reply) ||
      !CU_add_test(pSuite, "submit_headers_push_reply",
                   test_nghttp2_submit_headers_push_reply) ||
      !CU_add_test(pSuite, "submit_headers", test_nghttp2_submit_headers) ||
      !CU_add_test(pSuite, "submit_headers_continuation",
                   test_nghttp2_submit_headers_continuation) ||
      !CU_add_test(pSuite, "submit_headers_continuation_extra_large",
                   test_nghttp2_submit_headers_continuation_extra_large) ||
      !CU_add_test(pSuite, "submit_priority", test_nghttp2_submit_priority) ||
      !CU_add_test(pSuite, "session_submit_settings",
                   test_nghttp2_submit_settings) ||
      !CU_add_test(pSuite, "session_submit_settings_update_local_window_size",
                   test_nghttp2_submit_settings_update_local_window_size) ||
      !CU_add_test(pSuite, "session_submit_settings_multiple_times",
                   test_nghttp2_submit_settings_multiple_times) ||
      !CU_add_test(pSuite, "session_submit_push_promise",
                   test_nghttp2_submit_push_promise) ||
      !CU_add_test(pSuite, "submit_window_update",
                   test_nghttp2_submit_window_update) ||
      !CU_add_test(pSuite, "submit_window_update_local_window_size",
                   test_nghttp2_submit_window_update_local_window_size) ||
      !CU_add_test(pSuite, "submit_shutdown_notice",
                   test_nghttp2_submit_shutdown_notice) ||
      !CU_add_test(pSuite, "submit_invalid_nv",
                   test_nghttp2_submit_invalid_nv) ||
      !CU_add_test(pSuite, "submit_extension", test_nghttp2_submit_extension) ||
      !CU_add_test(pSuite, "submit_altsvc", test_nghttp2_submit_altsvc) ||
      !CU_add_test(pSuite, "submit_origin", test_nghttp2_submit_origin) ||
      !CU_add_test(pSuite, "submit_priority_update",
                   test_nghttp2_submit_priority_update) ||
      !CU_add_test(pSuite, "submit_rst_stream",
                   test_nghttp2_submit_rst_stream) ||
      !CU_add_test(pSuite, "session_open_stream",
                   test_nghttp2_session_open_stream) ||
      !CU_add_test(pSuite, "session_open_stream_with_idle_stream_dep",
                   test_nghttp2_session_open_stream_with_idle_stream_dep) ||
      !CU_add_test(pSuite, "session_get_next_ob_item",
                   test_nghttp2_session_get_next_ob_item) ||
      !CU_add_test(pSuite, "session_pop_next_ob_item",
                   test_nghttp2_session_pop_next_ob_item) ||
      !CU_add_test(pSuite, "session_reply_fail",
                   test_nghttp2_session_reply_fail) ||
      !CU_add_test(pSuite, "session_max_concurrent_streams",
                   test_nghttp2_session_max_concurrent_streams) ||
      !CU_add_test(pSuite, "session_stop_data_with_rst_stream",
                   test_nghttp2_session_stop_data_with_rst_stream) ||
      !CU_add_test(pSuite, "session_defer_data",
                   test_nghttp2_session_defer_data) ||
      !CU_add_test(pSuite, "session_flow_control",
                   test_nghttp2_session_flow_control) ||
      !CU_add_test(pSuite, "session_flow_control_data_recv",
                   test_nghttp2_session_flow_control_data_recv) ||
      !CU_add_test(pSuite, "session_flow_control_data_with_padding_recv",
                   test_nghttp2_session_flow_control_data_with_padding_recv) ||
      !CU_add_test(pSuite, "session_data_read_temporal_failure",
                   test_nghttp2_session_data_read_temporal_failure) ||
      !CU_add_test(pSuite, "session_on_stream_close",
                   test_nghttp2_session_on_stream_close) ||
      !CU_add_test(pSuite, "session_on_ctrl_not_send",
                   test_nghttp2_session_on_ctrl_not_send) ||
      !CU_add_test(pSuite, "session_get_outbound_queue_size",
                   test_nghttp2_session_get_outbound_queue_size) ||
      !CU_add_test(pSuite, "session_get_effective_local_window_size",
                   test_nghttp2_session_get_effective_local_window_size) ||
      !CU_add_test(pSuite, "session_set_option",
                   test_nghttp2_session_set_option) ||
      !CU_add_test(pSuite, "session_data_backoff_by_high_pri_frame",
                   test_nghttp2_session_data_backoff_by_high_pri_frame) ||
      !CU_add_test(pSuite, "session_pack_data_with_padding",
                   test_nghttp2_session_pack_data_with_padding) ||
      !CU_add_test(pSuite, "session_pack_headers_with_padding",
                   test_nghttp2_session_pack_headers_with_padding) ||
      !CU_add_test(pSuite, "pack_settings_payload",
                   test_nghttp2_pack_settings_payload) ||
      !CU_add_test(pSuite, "session_stream_dep_add",
                   test_nghttp2_session_stream_dep_add) ||
      !CU_add_test(pSuite, "session_stream_dep_remove",
                   test_nghttp2_session_stream_dep_remove) ||
      !CU_add_test(pSuite, "session_stream_dep_add_subtree",
                   test_nghttp2_session_stream_dep_add_subtree) ||
      !CU_add_test(pSuite, "session_stream_dep_remove_subtree",
                   test_nghttp2_session_stream_dep_remove_subtree) ||
      !CU_add_test(
          pSuite, "session_stream_dep_all_your_stream_are_belong_to_us",
          test_nghttp2_session_stream_dep_all_your_stream_are_belong_to_us) ||
      !CU_add_test(pSuite, "session_stream_attach_item",
                   test_nghttp2_session_stream_attach_item) ||
      !CU_add_test(pSuite, "session_stream_attach_item_subtree",
                   test_nghttp2_session_stream_attach_item_subtree) ||
      !CU_add_test(pSuite, "session_stream_get_state",
                   test_nghttp2_session_stream_get_state) ||
      !CU_add_test(pSuite, "session_stream_get_something",
                   test_nghttp2_session_stream_get_something) ||
      !CU_add_test(pSuite, "session_find_stream",
                   test_nghttp2_session_find_stream) ||
      !CU_add_test(pSuite, "session_keep_closed_stream",
                   test_nghttp2_session_keep_closed_stream) ||
      !CU_add_test(pSuite, "session_keep_idle_stream",
                   test_nghttp2_session_keep_idle_stream) ||
      !CU_add_test(pSuite, "session_detach_idle_stream",
                   test_nghttp2_session_detach_idle_stream) ||
      !CU_add_test(pSuite, "session_large_dep_tree",
                   test_nghttp2_session_large_dep_tree) ||
      !CU_add_test(pSuite, "session_graceful_shutdown",
                   test_nghttp2_session_graceful_shutdown) ||
      !CU_add_test(pSuite, "session_on_header_temporal_failure",
                   test_nghttp2_session_on_header_temporal_failure) ||
      !CU_add_test(pSuite, "session_recv_client_magic",
                   test_nghttp2_session_recv_client_magic) ||
      !CU_add_test(pSuite, "session_delete_data_item",
                   test_nghttp2_session_delete_data_item) ||
      !CU_add_test(pSuite, "session_open_idle_stream",
                   test_nghttp2_session_open_idle_stream) ||
      !CU_add_test(pSuite, "session_cancel_reserved_remote",
                   test_nghttp2_session_cancel_reserved_remote) ||
      !CU_add_test(pSuite, "session_reset_pending_headers",
                   test_nghttp2_session_reset_pending_headers) ||
      !CU_add_test(pSuite, "session_send_data_callback",
                   test_nghttp2_session_send_data_callback) ||
      !CU_add_test(pSuite, "session_on_begin_headers_temporal_failure",
                   test_nghttp2_session_on_begin_headers_temporal_failure) ||
      !CU_add_test(pSuite, "session_defer_then_close",
                   test_nghttp2_session_defer_then_close) ||
      !CU_add_test(pSuite, "session_detach_item_from_closed_stream",
                   test_nghttp2_session_detach_item_from_closed_stream) ||
      !CU_add_test(pSuite, "session_flooding", test_nghttp2_session_flooding) ||
      !CU_add_test(pSuite, "session_change_stream_priority",
                   test_nghttp2_session_change_stream_priority) ||
      !CU_add_test(pSuite, "session_change_extpri_stream_priority",
                   test_nghttp2_session_change_extpri_stream_priority) ||
      !CU_add_test(pSuite, "session_create_idle_stream",
                   test_nghttp2_session_create_idle_stream) ||
      !CU_add_test(pSuite, "session_repeated_priority_change",
                   test_nghttp2_session_repeated_priority_change) ||
      !CU_add_test(pSuite, "session_repeated_priority_submission",
                   test_nghttp2_session_repeated_priority_submission) ||
      !CU_add_test(pSuite, "session_set_local_window_size",
                   test_nghttp2_session_set_local_window_size) ||
      !CU_add_test(pSuite, "session_cancel_from_before_frame_send",
                   test_nghttp2_session_cancel_from_before_frame_send) ||
      !CU_add_test(pSuite, "session_too_many_settings",
                   test_nghttp2_session_too_many_settings) ||
      !CU_add_test(pSuite, "session_removed_closed_stream",
                   test_nghttp2_session_removed_closed_stream) ||
      !CU_add_test(pSuite, "session_pause_data",
                   test_nghttp2_session_pause_data) ||
      !CU_add_test(pSuite, "session_no_closed_streams",
                   test_nghttp2_session_no_closed_streams) ||
      !CU_add_test(pSuite, "session_set_stream_user_data",
                   test_nghttp2_session_set_stream_user_data) ||
      !CU_add_test(pSuite, "session_no_rfc7540_priorities",
                   test_nghttp2_session_no_rfc7540_priorities) ||
      !CU_add_test(pSuite, "session_server_fallback_rfc7540_priorities",
                   test_nghttp2_session_server_fallback_rfc7540_priorities) ||
      !CU_add_test(pSuite, "session_stream_reset_ratelim",
                   test_nghttp2_session_stream_reset_ratelim) ||
      !CU_add_test(pSuite, "http_mandatory_headers",
                   test_nghttp2_http_mandatory_headers) ||
      !CU_add_test(pSuite, "http_content_length",
                   test_nghttp2_http_content_length) ||
      !CU_add_test(pSuite, "http_content_length_mismatch",
                   test_nghttp2_http_content_length_mismatch) ||
      !CU_add_test(pSuite, "http_non_final_response",
                   test_nghttp2_http_non_final_response) ||
      !CU_add_test(pSuite, "http_trailer_headers",
                   test_nghttp2_http_trailer_headers) ||
      !CU_add_test(pSuite, "http_ignore_regular_header",
                   test_nghttp2_http_ignore_regular_header) ||
      !CU_add_test(pSuite, "http_ignore_content_length",
                   test_nghttp2_http_ignore_content_length) ||
      !CU_add_test(pSuite, "http_record_request_method",
                   test_nghttp2_http_record_request_method) ||
      !CU_add_test(pSuite, "http_push_promise",
                   test_nghttp2_http_push_promise) ||
      !CU_add_test(pSuite, "http_head_method_upgrade_workaround",
                   test_nghttp2_http_head_method_upgrade_workaround) ||
      !CU_add_test(
          pSuite, "http_no_rfc9113_leading_and_trailing_ws_validation",
          test_nghttp2_http_no_rfc9113_leading_and_trailing_ws_validation) ||
      !CU_add_test(pSuite, "frame_pack_headers",
                   test_nghttp2_frame_pack_headers) ||
      !CU_add_test(pSuite, "frame_pack_headers_frame_too_large",
                   test_nghttp2_frame_pack_headers_frame_too_large) ||
      !CU_add_test(pSuite, "frame_pack_priority",
                   test_nghttp2_frame_pack_priority) ||
      !CU_add_test(pSuite, "frame_pack_rst_stream",
                   test_nghttp2_frame_pack_rst_stream) ||
      !CU_add_test(pSuite, "frame_pack_settings",
                   test_nghttp2_frame_pack_settings) ||
      !CU_add_test(pSuite, "frame_pack_push_promise",
                   test_nghttp2_frame_pack_push_promise) ||
      !CU_add_test(pSuite, "frame_pack_ping", test_nghttp2_frame_pack_ping) ||
      !CU_add_test(pSuite, "frame_pack_goaway",
                   test_nghttp2_frame_pack_goaway) ||
      !CU_add_test(pSuite, "frame_pack_window_update",
                   test_nghttp2_frame_pack_window_update) ||
      !CU_add_test(pSuite, "frame_pack_altsvc",
                   test_nghttp2_frame_pack_altsvc) ||
      !CU_add_test(pSuite, "frame_pack_origin",
                   test_nghttp2_frame_pack_origin) ||
      !CU_add_test(pSuite, "frame_pack_priority_update",
                   test_nghttp2_frame_pack_priority_update) ||
      !CU_add_test(pSuite, "nv_array_copy", test_nghttp2_nv_array_copy) ||
      !CU_add_test(pSuite, "iv_check", test_nghttp2_iv_check) ||
      !CU_add_test(pSuite, "hd_deflate", test_nghttp2_hd_deflate) ||
      !CU_add_test(pSuite, "hd_deflate_same_indexed_repr",
                   test_nghttp2_hd_deflate_same_indexed_repr) ||
      !CU_add_test(pSuite, "hd_inflate_indexed",
                   test_nghttp2_hd_inflate_indexed) ||
      !CU_add_test(pSuite, "hd_inflate_indname_noinc",
                   test_nghttp2_hd_inflate_indname_noinc) ||
      !CU_add_test(pSuite, "hd_inflate_indname_inc",
                   test_nghttp2_hd_inflate_indname_inc) ||
      !CU_add_test(pSuite, "hd_inflate_indname_inc_eviction",
                   test_nghttp2_hd_inflate_indname_inc_eviction) ||
      !CU_add_test(pSuite, "hd_inflate_newname_noinc",
                   test_nghttp2_hd_inflate_newname_noinc) ||
      !CU_add_test(pSuite, "hd_inflate_newname_inc",
                   test_nghttp2_hd_inflate_newname_inc) ||
      !CU_add_test(pSuite, "hd_inflate_clearall_inc",
                   test_nghttp2_hd_inflate_clearall_inc) ||
      !CU_add_test(pSuite, "hd_inflate_zero_length_huffman",
                   test_nghttp2_hd_inflate_zero_length_huffman) ||
      !CU_add_test(pSuite, "hd_inflate_expect_table_size_update",
                   test_nghttp2_hd_inflate_expect_table_size_update) ||
      !CU_add_test(pSuite, "hd_inflate_unexpected_table_size_update",
                   test_nghttp2_hd_inflate_unexpected_table_size_update) ||
      !CU_add_test(pSuite, "hd_ringbuf_reserve",
                   test_nghttp2_hd_ringbuf_reserve) ||
      !CU_add_test(pSuite, "hd_change_table_size",
                   test_nghttp2_hd_change_table_size) ||
      !CU_add_test(pSuite, "hd_deflate_inflate",
                   test_nghttp2_hd_deflate_inflate) ||
      !CU_add_test(pSuite, "hd_no_index", test_nghttp2_hd_no_index) ||
      !CU_add_test(pSuite, "hd_deflate_bound", test_nghttp2_hd_deflate_bound) ||
      !CU_add_test(pSuite, "hd_public_api", test_nghttp2_hd_public_api) ||
      !CU_add_test(pSuite, "hd_deflate_hd_vec",
                   test_nghttp2_hd_deflate_hd_vec) ||
      !CU_add_test(pSuite, "hd_decode_length", test_nghttp2_hd_decode_length) ||
      !CU_add_test(pSuite, "hd_huff_encode", test_nghttp2_hd_huff_encode) ||
      !CU_add_test(pSuite, "hd_huff_decode", test_nghttp2_hd_huff_decode) ||
      !CU_add_test(pSuite, "adjust_local_window_size",
                   test_nghttp2_adjust_local_window_size) ||
      !CU_add_test(pSuite, "check_header_name",
                   test_nghttp2_check_header_name) ||
      !CU_add_test(pSuite, "check_header_value",
                   test_nghttp2_check_header_value) ||
      !CU_add_test(pSuite, "check_header_value_rfc9113",
                   test_nghttp2_check_header_value_rfc9113) ||
      !CU_add_test(pSuite, "bufs_add", test_nghttp2_bufs_add) ||
      !CU_add_test(pSuite, "bufs_add_stack_buffer_overflow_bug",
                   test_nghttp2_bufs_add_stack_buffer_overflow_bug) ||
      !CU_add_test(pSuite, "bufs_addb", test_nghttp2_bufs_addb) ||
      !CU_add_test(pSuite, "bufs_orb", test_nghttp2_bufs_orb) ||
      !CU_add_test(pSuite, "bufs_remove", test_nghttp2_bufs_remove) ||
      !CU_add_test(pSuite, "bufs_reset", test_nghttp2_bufs_reset) ||
      !CU_add_test(pSuite, "bufs_advance", test_nghttp2_bufs_advance) ||
      !CU_add_test(pSuite, "bufs_next_present",
                   test_nghttp2_bufs_next_present) ||
      !CU_add_test(pSuite, "bufs_realloc", test_nghttp2_bufs_realloc) ||
      !CU_add_test(pSuite, "http_parse_priority",
                   test_nghttp2_http_parse_priority) ||
      !CU_add_test(pSuite, "extpri_to_uint8", test_nghttp2_extpri_to_uint8) ||
      !CU_add_test(pSuite, "ratelim_update", test_nghttp2_ratelim_update) ||
      !CU_add_test(pSuite, "ratelim_drain", test_nghttp2_ratelim_drain)) {
    CU_cleanup_registry();
    return (int)CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  num_tests_failed = CU_get_number_of_tests_failed();
  CU_cleanup_registry();
  if (CU_get_error() == CUE_SUCCESS) {
    return (int)num_tests_failed;
  } else {
    printf("CUnit Error: %s\n", CU_get_error_msg());
    return (int)CU_get_error();
  }
}
