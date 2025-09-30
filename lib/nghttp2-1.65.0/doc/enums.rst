
Enums
=====
.. type:: nghttp2_error

    
    Error codes used in this library.  The code range is [-999, -500],
    inclusive. The following values are defined:

    .. enum:: NGHTTP2_ERR_INVALID_ARGUMENT

        (``-501``) 
        Invalid argument passed.
    .. enum:: NGHTTP2_ERR_BUFFER_ERROR

        (``-502``) 
        Out of buffer space.
    .. enum:: NGHTTP2_ERR_UNSUPPORTED_VERSION

        (``-503``) 
        The specified protocol version is not supported.
    .. enum:: NGHTTP2_ERR_WOULDBLOCK

        (``-504``) 
        Used as a return value from :type:`nghttp2_send_callback2`,
        :type:`nghttp2_recv_callback` and
        :type:`nghttp2_send_data_callback` to indicate that the operation
        would block.
    .. enum:: NGHTTP2_ERR_PROTO

        (``-505``) 
        General protocol error
    .. enum:: NGHTTP2_ERR_INVALID_FRAME

        (``-506``) 
        The frame is invalid.
    .. enum:: NGHTTP2_ERR_EOF

        (``-507``) 
        The peer performed a shutdown on the connection.
    .. enum:: NGHTTP2_ERR_DEFERRED

        (``-508``) 
        Used as a return value from
        :func:`nghttp2_data_source_read_callback2` to indicate that data
        transfer is postponed.  See
        :func:`nghttp2_data_source_read_callback2` for details.
    .. enum:: NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE

        (``-509``) 
        Stream ID has reached the maximum value.  Therefore no stream ID
        is available.
    .. enum:: NGHTTP2_ERR_STREAM_CLOSED

        (``-510``) 
        The stream is already closed; or the stream ID is invalid.
    .. enum:: NGHTTP2_ERR_STREAM_CLOSING

        (``-511``) 
        RST_STREAM has been added to the outbound queue.  The stream is
        in closing state.
    .. enum:: NGHTTP2_ERR_STREAM_SHUT_WR

        (``-512``) 
        The transmission is not allowed for this stream (e.g., a frame
        with END_STREAM flag set has already sent).
    .. enum:: NGHTTP2_ERR_INVALID_STREAM_ID

        (``-513``) 
        The stream ID is invalid.
    .. enum:: NGHTTP2_ERR_INVALID_STREAM_STATE

        (``-514``) 
        The state of the stream is not valid (e.g., DATA cannot be sent
        to the stream if response HEADERS has not been sent).
    .. enum:: NGHTTP2_ERR_DEFERRED_DATA_EXIST

        (``-515``) 
        Another DATA frame has already been deferred.
    .. enum:: NGHTTP2_ERR_START_STREAM_NOT_ALLOWED

        (``-516``) 
        Starting new stream is not allowed (e.g., GOAWAY has been sent
        and/or received).
    .. enum:: NGHTTP2_ERR_GOAWAY_ALREADY_SENT

        (``-517``) 
        GOAWAY has already been sent.
    .. enum:: NGHTTP2_ERR_INVALID_HEADER_BLOCK

        (``-518``) 
        The received frame contains the invalid header block (e.g., There
        are duplicate header names; or the header names are not encoded
        in US-ASCII character set and not lower cased; or the header name
        is zero-length string; or the header value contains multiple
        in-sequence NUL bytes).
    .. enum:: NGHTTP2_ERR_INVALID_STATE

        (``-519``) 
        Indicates that the context is not suitable to perform the
        requested operation.
    .. enum:: NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE

        (``-521``) 
        The user callback function failed due to the temporal error.
    .. enum:: NGHTTP2_ERR_FRAME_SIZE_ERROR

        (``-522``) 
        The length of the frame is invalid, either too large or too small.
    .. enum:: NGHTTP2_ERR_HEADER_COMP

        (``-523``) 
        Header block inflate/deflate error.
    .. enum:: NGHTTP2_ERR_FLOW_CONTROL

        (``-524``) 
        Flow control error
    .. enum:: NGHTTP2_ERR_INSUFF_BUFSIZE

        (``-525``) 
        Insufficient buffer size given to function.
    .. enum:: NGHTTP2_ERR_PAUSE

        (``-526``) 
        Callback was paused by the application
    .. enum:: NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS

        (``-527``) 
        There are too many in-flight SETTING frame and no more
        transmission of SETTINGS is allowed.
    .. enum:: NGHTTP2_ERR_PUSH_DISABLED

        (``-528``) 
        The server push is disabled.
    .. enum:: NGHTTP2_ERR_DATA_EXIST

        (``-529``) 
        DATA or HEADERS frame for a given stream has been already
        submitted and has not been fully processed yet.  Application
        should wait for the transmission of the previously submitted
        frame before submitting another.
    .. enum:: NGHTTP2_ERR_SESSION_CLOSING

        (``-530``) 
        The current session is closing due to a connection error or
        `nghttp2_session_terminate_session()` is called.
    .. enum:: NGHTTP2_ERR_HTTP_HEADER

        (``-531``) 
        Invalid HTTP header field was received and stream is going to be
        closed.
    .. enum:: NGHTTP2_ERR_HTTP_MESSAGING

        (``-532``) 
        Violation in HTTP messaging rule.
    .. enum:: NGHTTP2_ERR_REFUSED_STREAM

        (``-533``) 
        Stream was refused.
    .. enum:: NGHTTP2_ERR_INTERNAL

        (``-534``) 
        Unexpected internal error, but recovered.
    .. enum:: NGHTTP2_ERR_CANCEL

        (``-535``) 
        Indicates that a processing was canceled.
    .. enum:: NGHTTP2_ERR_SETTINGS_EXPECTED

        (``-536``) 
        When a local endpoint expects to receive SETTINGS frame, it
        receives an other type of frame.
    .. enum:: NGHTTP2_ERR_TOO_MANY_SETTINGS

        (``-537``) 
        When a local endpoint receives too many settings entries
        in a single SETTINGS frame.
    .. enum:: NGHTTP2_ERR_FATAL

        (``-900``) 
        The errors < :enum:`nghttp2_error.NGHTTP2_ERR_FATAL` mean that
        the library is under unexpected condition and processing was
        terminated (e.g., out of memory).  If application receives this
        error code, it must stop using that :type:`nghttp2_session`
        object and only allowed operation for that object is deallocate
        it using `nghttp2_session_del()`.
    .. enum:: NGHTTP2_ERR_NOMEM

        (``-901``) 
        Out of memory.  This is a fatal error.
    .. enum:: NGHTTP2_ERR_CALLBACK_FAILURE

        (``-902``) 
        The user callback function failed.  This is a fatal error.
    .. enum:: NGHTTP2_ERR_BAD_CLIENT_MAGIC

        (``-903``) 
        Invalid client magic (see :macro:`NGHTTP2_CLIENT_MAGIC`) was
        received and further processing is not possible.
    .. enum:: NGHTTP2_ERR_FLOODED

        (``-904``) 
        Possible flooding by peer was detected in this HTTP/2 session.
        Flooding is measured by how many PING and SETTINGS frames with
        ACK flag set are queued for transmission.  These frames are
        response for the peer initiated frames, and peer can cause memory
        exhaustion on server side to send these frames forever and does
        not read network.
    .. enum:: NGHTTP2_ERR_TOO_MANY_CONTINUATIONS

        (``-905``) 
        When a local endpoint receives too many CONTINUATION frames
        following a HEADER frame.

.. type:: nghttp2_nv_flag

    
    The flags for header field name/value pair.

    .. enum:: NGHTTP2_NV_FLAG_NONE

        (``0``) 
        No flag set.
    .. enum:: NGHTTP2_NV_FLAG_NO_INDEX

        (``0x01``) 
        Indicates that this name/value pair must not be indexed ("Literal
        Header Field never Indexed" representation must be used in HPACK
        encoding).  Other implementation calls this bit as "sensitive".
    .. enum:: NGHTTP2_NV_FLAG_NO_COPY_NAME

        (``0x02``) 
        This flag is set solely by application.  If this flag is set, the
        library does not make a copy of header field name.  This could
        improve performance.
    .. enum:: NGHTTP2_NV_FLAG_NO_COPY_VALUE

        (``0x04``) 
        This flag is set solely by application.  If this flag is set, the
        library does not make a copy of header field value.  This could
        improve performance.

.. type:: nghttp2_frame_type

    
    The frame types in HTTP/2 specification.

    .. enum:: NGHTTP2_DATA

        (``0``) 
        The DATA frame.
    .. enum:: NGHTTP2_HEADERS

        (``0x01``) 
        The HEADERS frame.
    .. enum:: NGHTTP2_PRIORITY

        (``0x02``) 
        The PRIORITY frame.
    .. enum:: NGHTTP2_RST_STREAM

        (``0x03``) 
        The RST_STREAM frame.
    .. enum:: NGHTTP2_SETTINGS

        (``0x04``) 
        The SETTINGS frame.
    .. enum:: NGHTTP2_PUSH_PROMISE

        (``0x05``) 
        The PUSH_PROMISE frame.
    .. enum:: NGHTTP2_PING

        (``0x06``) 
        The PING frame.
    .. enum:: NGHTTP2_GOAWAY

        (``0x07``) 
        The GOAWAY frame.
    .. enum:: NGHTTP2_WINDOW_UPDATE

        (``0x08``) 
        The WINDOW_UPDATE frame.
    .. enum:: NGHTTP2_CONTINUATION

        (``0x09``) 
        The CONTINUATION frame.  This frame type won't be passed to any
        callbacks because the library processes this frame type and its
        preceding HEADERS/PUSH_PROMISE as a single frame.
    .. enum:: NGHTTP2_ALTSVC

        (``0x0a``) 
        The ALTSVC frame, which is defined in `RFC 7383
        <https://tools.ietf.org/html/rfc7838#section-4>`_.
    .. enum:: NGHTTP2_ORIGIN

        (``0x0c``) 
        The ORIGIN frame, which is defined by `RFC 8336
        <https://tools.ietf.org/html/rfc8336>`_.
    .. enum:: NGHTTP2_PRIORITY_UPDATE

        (``0x10``) 
        The PRIORITY_UPDATE frame, which is defined by :rfc:`9218`.

.. type:: nghttp2_flag

    
    The flags for HTTP/2 frames.  This enum defines all flags for all
    frames.

    .. enum:: NGHTTP2_FLAG_NONE

        (``0``) 
        No flag set.
    .. enum:: NGHTTP2_FLAG_END_STREAM

        (``0x01``) 
        The END_STREAM flag.
    .. enum:: NGHTTP2_FLAG_END_HEADERS

        (``0x04``) 
        The END_HEADERS flag.
    .. enum:: NGHTTP2_FLAG_ACK

        (``0x01``) 
        The ACK flag.
    .. enum:: NGHTTP2_FLAG_PADDED

        (``0x08``) 
        The PADDED flag.
    .. enum:: NGHTTP2_FLAG_PRIORITY

        (``0x20``) 
        The PRIORITY flag.

.. type:: nghttp2_settings_id

    The SETTINGS ID.

    .. enum:: NGHTTP2_SETTINGS_HEADER_TABLE_SIZE

        (``0x01``) 
        SETTINGS_HEADER_TABLE_SIZE
    .. enum:: NGHTTP2_SETTINGS_ENABLE_PUSH

        (``0x02``) 
        SETTINGS_ENABLE_PUSH
    .. enum:: NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS

        (``0x03``) 
        SETTINGS_MAX_CONCURRENT_STREAMS
    .. enum:: NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE

        (``0x04``) 
        SETTINGS_INITIAL_WINDOW_SIZE
    .. enum:: NGHTTP2_SETTINGS_MAX_FRAME_SIZE

        (``0x05``) 
        SETTINGS_MAX_FRAME_SIZE
    .. enum:: NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE

        (``0x06``) 
        SETTINGS_MAX_HEADER_LIST_SIZE
    .. enum:: NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL

        (``0x08``) 
        SETTINGS_ENABLE_CONNECT_PROTOCOL
        (`RFC 8441 <https://tools.ietf.org/html/rfc8441>`_)
    .. enum:: NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES

        (``0x09``) 
        SETTINGS_NO_RFC7540_PRIORITIES (:rfc:`9218`)

.. type:: nghttp2_error_code

    The status codes for the RST_STREAM and GOAWAY frames.

    .. enum:: NGHTTP2_NO_ERROR

        (``0x00``) 
        No errors.
    .. enum:: NGHTTP2_PROTOCOL_ERROR

        (``0x01``) 
        PROTOCOL_ERROR
    .. enum:: NGHTTP2_INTERNAL_ERROR

        (``0x02``) 
        INTERNAL_ERROR
    .. enum:: NGHTTP2_FLOW_CONTROL_ERROR

        (``0x03``) 
        FLOW_CONTROL_ERROR
    .. enum:: NGHTTP2_SETTINGS_TIMEOUT

        (``0x04``) 
        SETTINGS_TIMEOUT
    .. enum:: NGHTTP2_STREAM_CLOSED

        (``0x05``) 
        STREAM_CLOSED
    .. enum:: NGHTTP2_FRAME_SIZE_ERROR

        (``0x06``) 
        FRAME_SIZE_ERROR
    .. enum:: NGHTTP2_REFUSED_STREAM

        (``0x07``) 
        REFUSED_STREAM
    .. enum:: NGHTTP2_CANCEL

        (``0x08``) 
        CANCEL
    .. enum:: NGHTTP2_COMPRESSION_ERROR

        (``0x09``) 
        COMPRESSION_ERROR
    .. enum:: NGHTTP2_CONNECT_ERROR

        (``0x0a``) 
        CONNECT_ERROR
    .. enum:: NGHTTP2_ENHANCE_YOUR_CALM

        (``0x0b``) 
        ENHANCE_YOUR_CALM
    .. enum:: NGHTTP2_INADEQUATE_SECURITY

        (``0x0c``) 
        INADEQUATE_SECURITY
    .. enum:: NGHTTP2_HTTP_1_1_REQUIRED

        (``0x0d``) 
        HTTP_1_1_REQUIRED

.. type:: nghttp2_data_flag

    
    The flags used to set in *data_flags* output parameter in
    :type:`nghttp2_data_source_read_callback2`.

    .. enum:: NGHTTP2_DATA_FLAG_NONE

        (``0``) 
        No flag set.
    .. enum:: NGHTTP2_DATA_FLAG_EOF

        (``0x01``) 
        Indicates EOF was sensed.
    .. enum:: NGHTTP2_DATA_FLAG_NO_END_STREAM

        (``0x02``) 
        Indicates that END_STREAM flag must not be set even if
        NGHTTP2_DATA_FLAG_EOF is set.  Usually this flag is used to send
        trailer fields with `nghttp2_submit_request2()` or
        `nghttp2_submit_response2()`.
    .. enum:: NGHTTP2_DATA_FLAG_NO_COPY

        (``0x04``) 
        Indicates that application will send complete DATA frame in
        :type:`nghttp2_send_data_callback`.

.. type:: nghttp2_headers_category

    
    The category of HEADERS, which indicates the role of the frame.  In
    HTTP/2 spec, request, response, push response and other arbitrary
    headers (e.g., trailer fields) are all called just HEADERS.  To
    give the application the role of incoming HEADERS frame, we define
    several categories.

    .. enum:: NGHTTP2_HCAT_REQUEST

        (``0``) 
        The HEADERS frame is opening new stream, which is analogous to
        SYN_STREAM in SPDY.
    .. enum:: NGHTTP2_HCAT_RESPONSE

        (``1``) 
        The HEADERS frame is the first response headers, which is
        analogous to SYN_REPLY in SPDY.
    .. enum:: NGHTTP2_HCAT_PUSH_RESPONSE

        (``2``) 
        The HEADERS frame is the first headers sent against reserved
        stream.
    .. enum:: NGHTTP2_HCAT_HEADERS

        (``3``) 
        The HEADERS frame which does not apply for the above categories,
        which is analogous to HEADERS in SPDY.  If non-final response
        (e.g., status 1xx) is used, final response HEADERS frame will be
        categorized here.

.. type:: nghttp2_hd_inflate_flag

    
    The flags for header inflation.

    .. enum:: NGHTTP2_HD_INFLATE_NONE

        (``0``) 
        No flag set.
    .. enum:: NGHTTP2_HD_INFLATE_FINAL

        (``0x01``) 
        Indicates all headers were inflated.
    .. enum:: NGHTTP2_HD_INFLATE_EMIT

        (``0x02``) 
        Indicates a header was emitted.

.. type:: nghttp2_stream_proto_state

    
    State of stream as described in RFC 7540.

    .. enum:: NGHTTP2_STREAM_STATE_IDLE

        (``1``) 
        idle state.
    .. enum:: NGHTTP2_STREAM_STATE_OPEN

        open state.
    .. enum:: NGHTTP2_STREAM_STATE_RESERVED_LOCAL

        reserved (local) state.
    .. enum:: NGHTTP2_STREAM_STATE_RESERVED_REMOTE

        reserved (remote) state.
    .. enum:: NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL

        half closed (local) state.
    .. enum:: NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE

        half closed (remote) state.
    .. enum:: NGHTTP2_STREAM_STATE_CLOSED

        closed state.

