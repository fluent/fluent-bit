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
#ifndef NGHTTP2_SESSION_TEST_H
#define NGHTTP2_SESSION_TEST_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

void test_nghttp2_session_recv(void);
void test_nghttp2_session_recv_invalid_stream_id(void);
void test_nghttp2_session_recv_invalid_frame(void);
void test_nghttp2_session_recv_eof(void);
void test_nghttp2_session_recv_data(void);
void test_nghttp2_session_recv_data_no_auto_flow_control(void);
void test_nghttp2_session_recv_continuation(void);
void test_nghttp2_session_recv_headers_with_priority(void);
void test_nghttp2_session_recv_headers_with_padding(void);
void test_nghttp2_session_recv_headers_early_response(void);
void test_nghttp2_session_recv_headers_for_closed_stream(void);
void test_nghttp2_session_recv_headers_with_extpri(void);
void test_nghttp2_session_server_recv_push_response(void);
void test_nghttp2_session_recv_premature_headers(void);
void test_nghttp2_session_recv_unknown_frame(void);
void test_nghttp2_session_recv_unexpected_continuation(void);
void test_nghttp2_session_recv_settings_header_table_size(void);
void test_nghttp2_session_recv_too_large_frame_length(void);
void test_nghttp2_session_recv_extension(void);
void test_nghttp2_session_recv_altsvc(void);
void test_nghttp2_session_recv_origin(void);
void test_nghttp2_session_recv_priority_update(void);
void test_nghttp2_session_continue(void);
void test_nghttp2_session_add_frame(void);
void test_nghttp2_session_on_request_headers_received(void);
void test_nghttp2_session_on_response_headers_received(void);
void test_nghttp2_session_on_headers_received(void);
void test_nghttp2_session_on_push_response_headers_received(void);
void test_nghttp2_session_on_priority_received(void);
void test_nghttp2_session_on_rst_stream_received(void);
void test_nghttp2_session_on_settings_received(void);
void test_nghttp2_session_on_push_promise_received(void);
void test_nghttp2_session_on_ping_received(void);
void test_nghttp2_session_on_goaway_received(void);
void test_nghttp2_session_on_window_update_received(void);
void test_nghttp2_session_on_data_received(void);
void test_nghttp2_session_on_data_received_fail_fast(void);
void test_nghttp2_session_on_altsvc_received(void);
void test_nghttp2_session_send_headers_start_stream(void);
void test_nghttp2_session_send_headers_reply(void);
void test_nghttp2_session_send_headers_frame_size_error(void);
void test_nghttp2_session_send_headers_push_reply(void);
void test_nghttp2_session_send_rst_stream(void);
void test_nghttp2_session_send_push_promise(void);
void test_nghttp2_session_is_my_stream_id(void);
void test_nghttp2_session_upgrade2(void);
void test_nghttp2_session_reprioritize_stream(void);
void test_nghttp2_session_reprioritize_stream_with_idle_stream_dep(void);
void test_nghttp2_submit_data(void);
void test_nghttp2_submit_data_read_length_too_large(void);
void test_nghttp2_submit_data_read_length_smallest(void);
void test_nghttp2_submit_data_twice(void);
void test_nghttp2_submit_request_with_data(void);
void test_nghttp2_submit_request_without_data(void);
void test_nghttp2_submit_response_with_data(void);
void test_nghttp2_submit_response_without_data(void);
void test_nghttp2_submit_response_push_response(void);
void test_nghttp2_submit_trailer(void);
void test_nghttp2_submit_headers_start_stream(void);
void test_nghttp2_submit_headers_reply(void);
void test_nghttp2_submit_headers_push_reply(void);
void test_nghttp2_submit_headers(void);
void test_nghttp2_submit_headers_continuation(void);
void test_nghttp2_submit_headers_continuation_extra_large(void);
void test_nghttp2_submit_priority(void);
void test_nghttp2_submit_settings(void);
void test_nghttp2_submit_settings_update_local_window_size(void);
void test_nghttp2_submit_settings_multiple_times(void);
void test_nghttp2_submit_push_promise(void);
void test_nghttp2_submit_window_update(void);
void test_nghttp2_submit_window_update_local_window_size(void);
void test_nghttp2_submit_shutdown_notice(void);
void test_nghttp2_submit_invalid_nv(void);
void test_nghttp2_submit_extension(void);
void test_nghttp2_submit_altsvc(void);
void test_nghttp2_submit_origin(void);
void test_nghttp2_submit_priority_update(void);
void test_nghttp2_submit_rst_stream(void);
void test_nghttp2_session_open_stream(void);
void test_nghttp2_session_open_stream_with_idle_stream_dep(void);
void test_nghttp2_session_get_next_ob_item(void);
void test_nghttp2_session_pop_next_ob_item(void);
void test_nghttp2_session_reply_fail(void);
void test_nghttp2_session_max_concurrent_streams(void);
void test_nghttp2_session_stop_data_with_rst_stream(void);
void test_nghttp2_session_defer_data(void);
void test_nghttp2_session_flow_control(void);
void test_nghttp2_session_flow_control_data_recv(void);
void test_nghttp2_session_flow_control_data_with_padding_recv(void);
void test_nghttp2_session_data_read_temporal_failure(void);
void test_nghttp2_session_on_stream_close(void);
void test_nghttp2_session_on_ctrl_not_send(void);
void test_nghttp2_session_get_outbound_queue_size(void);
void test_nghttp2_session_get_effective_local_window_size(void);
void test_nghttp2_session_set_option(void);
void test_nghttp2_session_data_backoff_by_high_pri_frame(void);
void test_nghttp2_session_pack_data_with_padding(void);
void test_nghttp2_session_pack_headers_with_padding(void);
void test_nghttp2_pack_settings_payload(void);
void test_nghttp2_session_stream_dep_add(void);
void test_nghttp2_session_stream_dep_remove(void);
void test_nghttp2_session_stream_dep_add_subtree(void);
void test_nghttp2_session_stream_dep_remove_subtree(void);
void test_nghttp2_session_stream_dep_all_your_stream_are_belong_to_us(void);
void test_nghttp2_session_stream_attach_item(void);
void test_nghttp2_session_stream_attach_item_subtree(void);
void test_nghttp2_session_stream_get_state(void);
void test_nghttp2_session_stream_get_something(void);
void test_nghttp2_session_find_stream(void);
void test_nghttp2_session_keep_closed_stream(void);
void test_nghttp2_session_keep_idle_stream(void);
void test_nghttp2_session_detach_idle_stream(void);
void test_nghttp2_session_large_dep_tree(void);
void test_nghttp2_session_graceful_shutdown(void);
void test_nghttp2_session_on_header_temporal_failure(void);
void test_nghttp2_session_recv_client_magic(void);
void test_nghttp2_session_delete_data_item(void);
void test_nghttp2_session_open_idle_stream(void);
void test_nghttp2_session_cancel_reserved_remote(void);
void test_nghttp2_session_reset_pending_headers(void);
void test_nghttp2_session_send_data_callback(void);
void test_nghttp2_session_on_begin_headers_temporal_failure(void);
void test_nghttp2_session_defer_then_close(void);
void test_nghttp2_session_detach_item_from_closed_stream(void);
void test_nghttp2_session_flooding(void);
void test_nghttp2_session_change_stream_priority(void);
void test_nghttp2_session_change_extpri_stream_priority(void);
void test_nghttp2_session_create_idle_stream(void);
void test_nghttp2_session_repeated_priority_change(void);
void test_nghttp2_session_repeated_priority_submission(void);
void test_nghttp2_session_set_local_window_size(void);
void test_nghttp2_session_cancel_from_before_frame_send(void);
void test_nghttp2_session_too_many_settings(void);
void test_nghttp2_session_removed_closed_stream(void);
void test_nghttp2_session_pause_data(void);
void test_nghttp2_session_no_closed_streams(void);
void test_nghttp2_session_set_stream_user_data(void);
void test_nghttp2_session_no_rfc7540_priorities(void);
void test_nghttp2_session_server_fallback_rfc7540_priorities(void);
void test_nghttp2_session_stream_reset_ratelim(void);
void test_nghttp2_http_mandatory_headers(void);
void test_nghttp2_http_content_length(void);
void test_nghttp2_http_content_length_mismatch(void);
void test_nghttp2_http_non_final_response(void);
void test_nghttp2_http_trailer_headers(void);
void test_nghttp2_http_ignore_regular_header(void);
void test_nghttp2_http_ignore_content_length(void);
void test_nghttp2_http_record_request_method(void);
void test_nghttp2_http_push_promise(void);
void test_nghttp2_http_head_method_upgrade_workaround(void);
void test_nghttp2_http_no_rfc9113_leading_and_trailing_ws_validation(void);

#endif /* NGHTTP2_SESSION_TEST_H */
