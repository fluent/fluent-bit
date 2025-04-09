
Types (structs, unions and typedefs)
====================================
.. type:: ptrdiff_t nghttp2_ssize

    
    :type:`nghttp2_ssize` is a signed counterpart of size_t.
.. type:: nghttp2_session

    
    The primary structure to hold the resources needed for a HTTP/2
    session.  The details of this structure are intentionally hidden
    from the public API.


.. type:: nghttp2_info

    
    This struct is what `nghttp2_version()` returns.  It holds
    information about the particular nghttp2 version.

    .. member::   int age

        Age of this struct.  This instance of nghttp2 sets it to
        :macro:`NGHTTP2_VERSION_AGE` but a future version may bump it and
        add more struct fields at the bottom
    .. member::   int version_num

        the :macro:`NGHTTP2_VERSION_NUM` number (since age ==1)
    .. member::   const char *version_str

        points to the :macro:`NGHTTP2_VERSION` string (since age ==1)
    .. member::   const char *proto_str

        points to the :macro:`NGHTTP2_PROTO_VERSION_ID` string this
        instance implements (since age ==1)

.. type:: nghttp2_vec

    
    The object representing single contiguous buffer.

    .. member::   uint8_t *base

        The pointer to the buffer.
    .. member::   size_t len

        The length of the buffer.

.. type:: nghttp2_rcbuf

    
    The object representing reference counted buffer.  The details of
    this structure are intentionally hidden from the public API.


.. type:: nghttp2_nv

    
    The name/value pair, which mainly used to represent header fields.

    .. member::   uint8_t *name

        The *name* byte string.  If this struct is presented from library
        (e.g., :type:`nghttp2_on_frame_recv_callback`), *name* is
        guaranteed to be NULL-terminated.  For some callbacks
        (:type:`nghttp2_before_frame_send_callback`,
        :type:`nghttp2_on_frame_send_callback`, and
        :type:`nghttp2_on_frame_not_send_callback`), it may not be
        NULL-terminated if header field is passed from application with
        the flag :enum:`nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_NAME`).
        When application is constructing this struct, *name* is not
        required to be NULL-terminated.
    .. member::   uint8_t *value

        The *value* byte string.  If this struct is presented from
        library (e.g., :type:`nghttp2_on_frame_recv_callback`), *value*
        is guaranteed to be NULL-terminated.  For some callbacks
        (:type:`nghttp2_before_frame_send_callback`,
        :type:`nghttp2_on_frame_send_callback`, and
        :type:`nghttp2_on_frame_not_send_callback`), it may not be
        NULL-terminated if header field is passed from application with
        the flag :enum:`nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_VALUE`).
        When application is constructing this struct, *value* is not
        required to be NULL-terminated.
    .. member::   size_t namelen

        The length of the *name*, excluding terminating NULL.
    .. member::   size_t valuelen

        The length of the *value*, excluding terminating NULL.
    .. member::   uint8_t flags

        Bitwise OR of one or more of :type:`nghttp2_nv_flag`.

.. type:: nghttp2_frame_hd

    The frame header.

    .. member::   size_t length

        The length field of this frame, excluding frame header.
    .. member::   int32_t stream_id

        The stream identifier (aka, stream ID)
    .. member::   uint8_t type

        The type of this frame.  See `nghttp2_frame_type`.
    .. member::   uint8_t flags

        The flags.
    .. member::   uint8_t reserved

        Reserved bit in frame header.  Currently, this is always set to 0
        and application should not expect something useful in here.

.. type:: nghttp2_data_source

    
    This union represents the some kind of data source passed to
    :type:`nghttp2_data_source_read_callback2`.

    .. member::   int fd

        The integer field, suitable for a file descriptor.
    .. member::   void *ptr

        The pointer to an arbitrary object.

.. type:: ssize_t (*nghttp2_data_source_read_callback)( nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)

    
    .. warning::
    
      Deprecated.  Use :type:`nghttp2_data_source_read_callback2`
      instead.
    
    Callback function invoked when the library wants to read data from
    the *source*.  The read data is sent in the stream *stream_id*.
    The implementation of this function must read at most *length*
    bytes of data from *source* (or possibly other places) and store
    them in *buf* and return number of data stored in *buf*.  If EOF is
    reached, set :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_EOF` flag
    in *\*data_flags*.
    
    Sometime it is desirable to avoid copying data into *buf* and let
    application to send data directly.  To achieve this, set
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_NO_COPY` to
    *\*data_flags* (and possibly other flags, just like when we do
    copy), and return the number of bytes to send without copying data
    into *buf*.  The library, seeing
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_NO_COPY`, will invoke
    :type:`nghttp2_send_data_callback`.  The application must send
    complete DATA frame in that callback.
    
    If this callback is set by `nghttp2_submit_request()`,
    `nghttp2_submit_response()` or `nghttp2_submit_headers()` and
    `nghttp2_submit_data()` with flag parameter
    :enum:`nghttp2_flag.NGHTTP2_FLAG_END_STREAM` set, and
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_EOF` flag is set to
    *\*data_flags*, DATA frame will have END_STREAM flag set.  Usually,
    this is expected behaviour and all are fine.  One exception is send
    trailer fields.  You cannot send trailer fields after sending frame
    with END_STREAM set.  To avoid this problem, one can set
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_NO_END_STREAM` along
    with :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_EOF` to signal the
    library not to set END_STREAM in DATA frame.  Then application can
    use `nghttp2_submit_trailer()` to send trailer fields.
    `nghttp2_submit_trailer()` can be called inside this callback.
    
    If the application wants to postpone DATA frames (e.g.,
    asynchronous I/O, or reading data blocks for long time), it is
    achieved by returning :enum:`nghttp2_error.NGHTTP2_ERR_DEFERRED`
    without reading any data in this invocation.  The library removes
    DATA frame from the outgoing queue temporarily.  To move back
    deferred DATA frame to outgoing queue, call
    `nghttp2_session_resume_data()`.
    
    By default, *length* is limited to 16KiB at maximum.  If peer
    allows larger frames, application can enlarge transmission buffer
    size.  See :type:`nghttp2_data_source_read_length_callback` for
    more details.
    
    If the application just wants to return from
    `nghttp2_session_send()` or `nghttp2_session_mem_send()` without
    sending anything, return :enum:`nghttp2_error.NGHTTP2_ERR_PAUSE`.
    
    In case of error, there are 2 choices. Returning
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will
    close the stream by issuing RST_STREAM with
    :enum:`nghttp2_error_code.NGHTTP2_INTERNAL_ERROR`.  If a different
    error code is desirable, use `nghttp2_submit_rst_stream()` with a
    desired error code and then return
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.
    Returning :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` will
    signal the entire session failure.
.. type:: nghttp2_ssize (*nghttp2_data_source_read_callback2)( nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)

    
    Callback function invoked when the library wants to read data from
    the *source*.  The read data is sent in the stream *stream_id*.
    The implementation of this function must read at most *length*
    bytes of data from *source* (or possibly other places) and store
    them in *buf* and return number of data stored in *buf*.  If EOF is
    reached, set :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_EOF` flag
    in *\*data_flags*.
    
    Sometime it is desirable to avoid copying data into *buf* and let
    application to send data directly.  To achieve this, set
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_NO_COPY` to
    *\*data_flags* (and possibly other flags, just like when we do
    copy), and return the number of bytes to send without copying data
    into *buf*.  The library, seeing
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_NO_COPY`, will invoke
    :type:`nghttp2_send_data_callback`.  The application must send
    complete DATA frame in that callback.
    
    If this callback is set by `nghttp2_submit_request2()`,
    `nghttp2_submit_response2()` or `nghttp2_submit_headers()` and
    `nghttp2_submit_data2()` with flag parameter
    :enum:`nghttp2_flag.NGHTTP2_FLAG_END_STREAM` set, and
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_EOF` flag is set to
    *\*data_flags*, DATA frame will have END_STREAM flag set.  Usually,
    this is expected behaviour and all are fine.  One exception is send
    trailer fields.  You cannot send trailer fields after sending frame
    with END_STREAM set.  To avoid this problem, one can set
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_NO_END_STREAM` along
    with :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_EOF` to signal the
    library not to set END_STREAM in DATA frame.  Then application can
    use `nghttp2_submit_trailer()` to send trailer fields.
    `nghttp2_submit_trailer()` can be called inside this callback.
    
    If the application wants to postpone DATA frames (e.g.,
    asynchronous I/O, or reading data blocks for long time), it is
    achieved by returning :enum:`nghttp2_error.NGHTTP2_ERR_DEFERRED`
    without reading any data in this invocation.  The library removes
    DATA frame from the outgoing queue temporarily.  To move back
    deferred DATA frame to outgoing queue, call
    `nghttp2_session_resume_data()`.
    
    By default, *length* is limited to 16KiB at maximum.  If peer
    allows larger frames, application can enlarge transmission buffer
    size.  See :type:`nghttp2_data_source_read_length_callback` for
    more details.
    
    If the application just wants to return from
    `nghttp2_session_send()` or `nghttp2_session_mem_send2()` without
    sending anything, return :enum:`nghttp2_error.NGHTTP2_ERR_PAUSE`.
    
    In case of error, there are 2 choices. Returning
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will
    close the stream by issuing RST_STREAM with
    :enum:`nghttp2_error_code.NGHTTP2_INTERNAL_ERROR`.  If a different
    error code is desirable, use `nghttp2_submit_rst_stream()` with a
    desired error code and then return
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.
    Returning :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` will
    signal the entire session failure.
.. type:: nghttp2_data_provider

    
    .. warning::
    
      Deprecated.  Use :type:`nghttp2_data_provider2` instead.
    
    This struct represents the data source and the way to read a chunk
    of data from it.

    .. member::   nghttp2_data_source source

        The data source.
    .. member::   nghttp2_data_source_read_callback read_callback

        The callback function to read a chunk of data from the *source*.

.. type:: nghttp2_data_provider2

    
    This struct represents the data source and the way to read a chunk
    of data from it.

    .. member::   nghttp2_data_source source

        The data source.
    .. member::   nghttp2_data_source_read_callback2 read_callback

        The callback function to read a chunk of data from the *source*.

.. type:: nghttp2_data

    
    The DATA frame.  The received data is delivered via
    :type:`nghttp2_on_data_chunk_recv_callback`.

    .. member::   size_t padlen

        The length of the padding in this frame.  This includes PAD_HIGH
        and PAD_LOW.

.. type:: nghttp2_priority_spec

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.
    
    The structure to specify stream dependency.

    .. member::   int32_t stream_id

        The stream ID of the stream to depend on.  Specifying 0 makes
        stream not depend any other stream.
    .. member::   int32_t weight

        The weight of this dependency.
    .. member::   uint8_t exclusive

        nonzero means exclusive dependency

.. type:: nghttp2_headers

    
    The HEADERS frame.  It has the following members:

    .. member::   nghttp2_frame_hd hd

        The frame header.
    .. member::   size_t padlen

        The length of the padding in this frame.  This includes PAD_HIGH
        and PAD_LOW.
    .. member::   nghttp2_priority_spec pri_spec

        .. warning::
        
          Deprecated.  :rfc:`7540` priorities are deprecated by
          :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
          prioritization scheme.
        
        The priority specification
    .. member::   nghttp2_nv *nva

        The name/value pairs.
    .. member::   size_t nvlen

        The number of name/value pairs in *nva*.
    .. member::   nghttp2_headers_category cat

        The category of this HEADERS frame.

.. type:: nghttp2_priority

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.
    
    The PRIORITY frame.  It has the following members:

    .. member::   nghttp2_frame_hd hd

        The frame header.
    .. member::   nghttp2_priority_spec pri_spec

        The priority specification.

.. type:: nghttp2_rst_stream

    
    The RST_STREAM frame.  It has the following members:

    .. member::   nghttp2_frame_hd hd

        The frame header.
    .. member::   uint32_t error_code

        The error code.  See :type:`nghttp2_error_code`.

.. type:: nghttp2_settings_entry

    
    The SETTINGS ID/Value pair.  It has the following members:

    .. member::   int32_t settings_id

        The SETTINGS ID.  See :type:`nghttp2_settings_id`.
    .. member::   uint32_t value

        The value of this entry.

.. type:: nghttp2_settings

    
    The SETTINGS frame.  It has the following members:

    .. member::   nghttp2_frame_hd hd

        The frame header.
    .. member::   size_t niv

        The number of SETTINGS ID/Value pairs in *iv*.
    .. member::   nghttp2_settings_entry *iv

        The pointer to the array of SETTINGS ID/Value pair.

.. type:: nghttp2_push_promise

    
    The PUSH_PROMISE frame.  It has the following members:

    .. member::   nghttp2_frame_hd hd

        The frame header.
    .. member::   size_t padlen

        The length of the padding in this frame.  This includes PAD_HIGH
        and PAD_LOW.
    .. member::   nghttp2_nv *nva

        The name/value pairs.
    .. member::   size_t nvlen

        The number of name/value pairs in *nva*.
    .. member::   int32_t promised_stream_id

        The promised stream ID
    .. member::   uint8_t reserved

        Reserved bit.  Currently this is always set to 0 and application
        should not expect something useful in here.

.. type:: nghttp2_ping

    
    The PING frame.  It has the following members:

    .. member::   nghttp2_frame_hd hd

        The frame header.
    .. member::   uint8_t opaque_data[8]

        The opaque data

.. type:: nghttp2_goaway

    
    The GOAWAY frame.  It has the following members:

    .. member::   nghttp2_frame_hd hd

        The frame header.
    .. member::   int32_t last_stream_id

        The last stream stream ID.
    .. member::   uint32_t error_code

        The error code.  See :type:`nghttp2_error_code`.
    .. member::   uint8_t *opaque_data

        The additional debug data
    .. member::   size_t opaque_data_len

        The length of *opaque_data* member.
    .. member::   uint8_t reserved

        Reserved bit.  Currently this is always set to 0 and application
        should not expect something useful in here.

.. type:: nghttp2_window_update

    
    The WINDOW_UPDATE frame.  It has the following members:

    .. member::   nghttp2_frame_hd hd

        The frame header.
    .. member::   int32_t window_size_increment

        The window size increment.
    .. member::   uint8_t reserved

        Reserved bit.  Currently this is always set to 0 and application
        should not expect something useful in here.

.. type:: nghttp2_extension

    
    The extension frame.  It has following members:

    .. member::   nghttp2_frame_hd hd

        The frame header.
    .. member::   void *payload

        The pointer to extension payload.  The exact pointer type is
        determined by hd.type.
        
        Currently, no extension is supported.  This is a place holder for
        the future extensions.

.. type:: nghttp2_frame

    
    This union includes all frames to pass them to various function
    calls as nghttp2_frame type.  The CONTINUATION frame is omitted
    from here because the library deals with it internally.

    .. member::   nghttp2_frame_hd hd

        The frame header, which is convenient to inspect frame header.
    .. member::   nghttp2_data data

        The DATA frame.
    .. member::   nghttp2_headers headers

        The HEADERS frame.
    .. member::   nghttp2_priority priority

        The PRIORITY frame.
    .. member::   nghttp2_rst_stream rst_stream

        The RST_STREAM frame.
    .. member::   nghttp2_settings settings

        The SETTINGS frame.
    .. member::   nghttp2_push_promise push_promise

        The PUSH_PROMISE frame.
    .. member::   nghttp2_ping ping

        The PING frame.
    .. member::   nghttp2_goaway goaway

        The GOAWAY frame.
    .. member::   nghttp2_window_update window_update

        The WINDOW_UPDATE frame.
    .. member::   nghttp2_extension ext

        The extension frame.

.. type:: ssize_t (*nghttp2_send_callback)(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)

    
    .. warning::
    
      Deprecated.  Use :type:`nghttp2_send_callback2` instead.
    
    Callback function invoked when *session* wants to send data to the
    remote peer.  The implementation of this function must send at most
    *length* bytes of data stored in *data*.  The *flags* is currently
    not used and always 0. It must return the number of bytes sent if
    it succeeds.  If it cannot send any single byte without blocking,
    it must return :enum:`nghttp2_error.NGHTTP2_ERR_WOULDBLOCK`.  For
    other errors, it must return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  The
    *user_data* pointer is the third argument passed in to the call to
    `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
    
    This callback is required if the application uses
    `nghttp2_session_send()` to send data to the remote endpoint.  If
    the application uses solely `nghttp2_session_mem_send()` instead,
    this callback function is unnecessary.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_send_callback()`.
    
    .. note::
    
      The *length* may be very small.  If that is the case, and
      application disables Nagle algorithm (``TCP_NODELAY``), then just
      writing *data* to the network stack leads to very small packet,
      and it is very inefficient.  An application should be responsible
      to buffer up small chunks of data as necessary to avoid this
      situation.
.. type:: nghttp2_ssize (*nghttp2_send_callback2)(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)

    
    Callback function invoked when *session* wants to send data to the
    remote peer.  The implementation of this function must send at most
    *length* bytes of data stored in *data*.  The *flags* is currently
    not used and always 0. It must return the number of bytes sent if
    it succeeds.  If it cannot send any single byte without blocking,
    it must return :enum:`nghttp2_error.NGHTTP2_ERR_WOULDBLOCK`.  For
    other errors, it must return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  The
    *user_data* pointer is the third argument passed in to the call to
    `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
    
    This callback is required if the application uses
    `nghttp2_session_send()` to send data to the remote endpoint.  If
    the application uses solely `nghttp2_session_mem_send2()` instead,
    this callback function is unnecessary.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_send_callback2()`.
    
    .. note::
    
      The *length* may be very small.  If that is the case, and
      application disables Nagle algorithm (``TCP_NODELAY``), then just
      writing *data* to the network stack leads to very small packet,
      and it is very inefficient.  An application should be responsible
      to buffer up small chunks of data as necessary to avoid this
      situation.
.. type:: int (*nghttp2_send_data_callback)(nghttp2_session *session, nghttp2_frame *frame, const uint8_t *framehd, size_t length, nghttp2_data_source *source, void *user_data)

    
    Callback function invoked when
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_NO_COPY` is used in
    :type:`nghttp2_data_source_read_callback` to send complete DATA
    frame.
    
    The *frame* is a DATA frame to send.  The *framehd* is the
    serialized frame header (9 bytes). The *length* is the length of
    application data to send (this does not include padding).  The
    *source* is the same pointer passed to
    :type:`nghttp2_data_source_read_callback`.
    
    The application first must send frame header *framehd* of length 9
    bytes.  If ``frame->data.padlen > 0``, send 1 byte of value
    ``frame->data.padlen - 1``.  Then send exactly *length* bytes of
    application data.  Finally, if ``frame->data.padlen > 1``, send
    ``frame->data.padlen - 1`` bytes of zero as padding.
    
    The application has to send complete DATA frame in this callback.
    If all data were written successfully, return 0.
    
    If it cannot send any data at all, just return
    :enum:`nghttp2_error.NGHTTP2_ERR_WOULDBLOCK`; the library will call
    this callback with the same parameters later (It is recommended to
    send complete DATA frame at once in this function to deal with
    error; if partial frame data has already sent, it is impossible to
    send another data in that state, and all we can do is tear down
    connection).  When data is fully processed, but application wants
    to make `nghttp2_session_mem_send2()` or `nghttp2_session_send()`
    return immediately without processing next frames, return
    :enum:`nghttp2_error.NGHTTP2_ERR_PAUSE`.  If application decided to
    reset this stream, return
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`, then
    the library will send RST_STREAM with INTERNAL_ERROR as error code.
    The application can also return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`, which will
    result in connection closure.  Returning any other value is treated
    as :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` is returned.
.. type:: ssize_t (*nghttp2_recv_callback)(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data)

    
    .. warning::
    
      Deprecated.  Use :type:`nghttp2_recv_callback2` instead.
    
    Callback function invoked when *session* wants to receive data from
    the remote peer.  The implementation of this function must read at
    most *length* bytes of data and store it in *buf*.  The *flags* is
    currently not used and always 0.  It must return the number of
    bytes written in *buf* if it succeeds.  If it cannot read any
    single byte without blocking, it must return
    :enum:`nghttp2_error.NGHTTP2_ERR_WOULDBLOCK`.  If it gets EOF
    before it reads any single byte, it must return
    :enum:`nghttp2_error.NGHTTP2_ERR_EOF`.  For other errors, it must
    return :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    Returning 0 is treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_WOULDBLOCK`.  The *user_data*
    pointer is the third argument passed in to the call to
    `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
    
    This callback is required if the application uses
    `nghttp2_session_recv()` to receive data from the remote endpoint.
    If the application uses solely `nghttp2_session_mem_recv()`
    instead, this callback function is unnecessary.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_recv_callback()`.
.. type:: nghttp2_ssize (*nghttp2_recv_callback2)(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data)

    
    Callback function invoked when *session* wants to receive data from
    the remote peer.  The implementation of this function must read at
    most *length* bytes of data and store it in *buf*.  The *flags* is
    currently not used and always 0.  It must return the number of
    bytes written in *buf* if it succeeds.  If it cannot read any
    single byte without blocking, it must return
    :enum:`nghttp2_error.NGHTTP2_ERR_WOULDBLOCK`.  If it gets EOF
    before it reads any single byte, it must return
    :enum:`nghttp2_error.NGHTTP2_ERR_EOF`.  For other errors, it must
    return :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    Returning 0 is treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_WOULDBLOCK`.  The *user_data*
    pointer is the third argument passed in to the call to
    `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
    
    This callback is required if the application uses
    `nghttp2_session_recv()` to receive data from the remote endpoint.
    If the application uses solely `nghttp2_session_mem_recv2()`
    instead, this callback function is unnecessary.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_recv_callback2()`.
.. type:: int (*nghttp2_on_frame_recv_callback)(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)

    
    Callback function invoked by `nghttp2_session_recv()` and
    `nghttp2_session_mem_recv2()` when a frame is received.  The
    *user_data* pointer is the third argument passed in to the call to
    `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
    
    If frame is HEADERS or PUSH_PROMISE, the ``nva`` and ``nvlen``
    member of their data structure are always ``NULL`` and 0
    respectively.  The header name/value pairs are emitted via
    :type:`nghttp2_on_header_callback`.
    
    Only HEADERS and DATA frame can signal the end of incoming data.
    If ``frame->hd.flags & NGHTTP2_FLAG_END_STREAM`` is nonzero, the
    *frame* is the last frame from the remote peer in this stream.
    
    This callback won't be called for CONTINUATION frames.
    HEADERS/PUSH_PROMISE + CONTINUATIONs are treated as single frame.
    
    The implementation of this function must return 0 if it succeeds.
    If nonzero value is returned, it is treated as fatal error and
    `nghttp2_session_recv()` and `nghttp2_session_mem_recv2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_on_frame_recv_callback()`.
.. type:: int (*nghttp2_on_invalid_frame_recv_callback)( nghttp2_session *session, const nghttp2_frame *frame, int lib_error_code, void *user_data)

    
    Callback function invoked by `nghttp2_session_recv()` and
    `nghttp2_session_mem_recv2()` when an invalid non-DATA frame is
    received.  The error is indicated by the *lib_error_code*, which is
    one of the values defined in :type:`nghttp2_error`.  When this
    callback function is invoked, the library automatically submits
    either RST_STREAM or GOAWAY frame.  The *user_data* pointer is the
    third argument passed in to the call to
    `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
    
    If frame is HEADERS or PUSH_PROMISE, the ``nva`` and ``nvlen``
    member of their data structure are always ``NULL`` and 0
    respectively.
    
    The implementation of this function must return 0 if it succeeds.
    If nonzero is returned, it is treated as fatal error and
    `nghttp2_session_recv()` and `nghttp2_session_mem_recv2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_on_invalid_frame_recv_callback()`.
.. type:: int (*nghttp2_on_data_chunk_recv_callback)(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)

    
    Callback function invoked when a chunk of data in DATA frame is
    received.  The *stream_id* is the stream ID this DATA frame belongs
    to.  The *flags* is the flags of DATA frame which this data chunk
    is contained.  ``(flags & NGHTTP2_FLAG_END_STREAM) != 0`` does not
    necessarily mean this chunk of data is the last one in the stream.
    You should use :type:`nghttp2_on_frame_recv_callback` to know all
    data frames are received.  The *user_data* pointer is the third
    argument passed in to the call to `nghttp2_session_client_new()` or
    `nghttp2_session_server_new()`.
    
    If the application uses `nghttp2_session_mem_recv2()`, it can
    return :enum:`nghttp2_error.NGHTTP2_ERR_PAUSE` to make
    `nghttp2_session_mem_recv2()` return without processing further
    input bytes.  The memory by pointed by the *data* is retained until
    `nghttp2_session_mem_recv2()` or `nghttp2_session_recv()` is
    called.  The application must retain the input bytes which was used
    to produce the *data* parameter, because it may refer to the memory
    region included in the input bytes.
    
    The implementation of this function must return 0 if it succeeds.
    If nonzero is returned, it is treated as fatal error, and
    `nghttp2_session_recv()` and `nghttp2_session_mem_recv2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_on_data_chunk_recv_callback()`.
.. type:: int (*nghttp2_before_frame_send_callback)(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)

    
    Callback function invoked just before the non-DATA frame *frame* is
    sent.  The *user_data* pointer is the third argument passed in to
    the call to `nghttp2_session_client_new()` or
    `nghttp2_session_server_new()`.
    
    The implementation of this function must return 0 if it succeeds.
    It can also return :enum:`nghttp2_error.NGHTTP2_ERR_CANCEL` to
    cancel the transmission of the given frame.
    
    If there is a fatal error while executing this callback, the
    implementation should return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`, which makes
    `nghttp2_session_send()` and `nghttp2_session_mem_send2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    If the other value is returned, it is treated as if
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` is returned.
    But the implementation should not rely on this since the library
    may define new return value to extend its capability.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_before_frame_send_callback()`.
.. type:: int (*nghttp2_on_frame_send_callback)(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)

    
    Callback function invoked after the frame *frame* is sent.  The
    *user_data* pointer is the third argument passed in to the call to
    `nghttp2_session_client_new()` or `nghttp2_session_server_new()`.
    
    The implementation of this function must return 0 if it succeeds.
    If nonzero is returned, it is treated as fatal error and
    `nghttp2_session_send()` and `nghttp2_session_mem_send2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_on_frame_send_callback()`.
.. type:: int (*nghttp2_on_frame_not_send_callback)(nghttp2_session *session, const nghttp2_frame *frame, int lib_error_code, void *user_data)

    
    Callback function invoked after the non-DATA frame *frame* is not
    sent because of the error.  The error is indicated by the
    *lib_error_code*, which is one of the values defined in
    :type:`nghttp2_error`.  The *user_data* pointer is the third
    argument passed in to the call to `nghttp2_session_client_new()` or
    `nghttp2_session_server_new()`.
    
    The implementation of this function must return 0 if it succeeds.
    If nonzero is returned, it is treated as fatal error and
    `nghttp2_session_send()` and `nghttp2_session_mem_send2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    `nghttp2_session_get_stream_user_data()` can be used to get
    associated data.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_on_frame_not_send_callback()`.
.. type:: int (*nghttp2_on_stream_close_callback)(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)

    
    Callback function invoked when the stream *stream_id* is closed.
    The reason of closure is indicated by the *error_code*.  The
    *error_code* is usually one of :enum:`nghttp2_error_code`, but that
    is not guaranteed.  The stream_user_data, which was specified in
    `nghttp2_submit_request2()` or `nghttp2_submit_headers()`, is still
    available in this function.  The *user_data* pointer is the third
    argument passed in to the call to `nghttp2_session_client_new()` or
    `nghttp2_session_server_new()`.
    
    This function is also called for a stream in reserved state.
    
    The implementation of this function must return 0 if it succeeds.
    If nonzero is returned, it is treated as fatal error and
    `nghttp2_session_recv()`, `nghttp2_session_mem_recv2()`,
    `nghttp2_session_send()`, and `nghttp2_session_mem_send2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_on_stream_close_callback()`.
.. type:: int (*nghttp2_on_begin_headers_callback)(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)

    
    Callback function invoked when the reception of header block in
    HEADERS or PUSH_PROMISE is started.  Each header name/value pair
    will be emitted by :type:`nghttp2_on_header_callback`.
    
    The ``frame->hd.flags`` may not have
    :enum:`nghttp2_flag.NGHTTP2_FLAG_END_HEADERS` flag set, which
    indicates that one or more CONTINUATION frames are involved.  But
    the application does not need to care about that because the header
    name/value pairs are emitted transparently regardless of
    CONTINUATION frames.
    
    The server applications probably create an object to store
    information about new stream if ``frame->hd.type ==
    NGHTTP2_HEADERS`` and ``frame->headers.cat ==
    NGHTTP2_HCAT_REQUEST``.  If *session* is configured as server side,
    ``frame->headers.cat`` is either ``NGHTTP2_HCAT_REQUEST``
    containing request headers or ``NGHTTP2_HCAT_HEADERS`` containing
    trailer fields and never get PUSH_PROMISE in this callback.
    
    For the client applications, ``frame->hd.type`` is either
    ``NGHTTP2_HEADERS`` or ``NGHTTP2_PUSH_PROMISE``.  In case of
    ``NGHTTP2_HEADERS``, ``frame->headers.cat ==
    NGHTTP2_HCAT_RESPONSE`` means that it is the first response
    headers, but it may be non-final response which is indicated by 1xx
    status code.  In this case, there may be zero or more HEADERS frame
    with ``frame->headers.cat == NGHTTP2_HCAT_HEADERS`` which has
    non-final response code and finally client gets exactly one HEADERS
    frame with ``frame->headers.cat == NGHTTP2_HCAT_HEADERS``
    containing final response headers (non-1xx status code).  The
    trailer fields also has ``frame->headers.cat ==
    NGHTTP2_HCAT_HEADERS`` which does not contain any status code.
    
    Returning
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will
    close the stream (promised stream if frame is PUSH_PROMISE) by
    issuing RST_STREAM with
    :enum:`nghttp2_error_code.NGHTTP2_INTERNAL_ERROR`.  In this case,
    :type:`nghttp2_on_header_callback` and
    :type:`nghttp2_on_frame_recv_callback` will not be invoked.  If a
    different error code is desirable, use
    `nghttp2_submit_rst_stream()` with a desired error code and then
    return :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.
    Again, use ``frame->push_promise.promised_stream_id`` as stream_id
    parameter in `nghttp2_submit_rst_stream()` if frame is
    PUSH_PROMISE.
    
    The implementation of this function must return 0 if it succeeds.
    It can return
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` to
    reset the stream (promised stream if frame is PUSH_PROMISE).  For
    critical errors, it must return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  If the other
    value is returned, it is treated as if
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` is returned.  If
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` is returned,
    `nghttp2_session_mem_recv2()` function will immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_on_begin_headers_callback()`.
.. type:: int (*nghttp2_on_header_callback)(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)

    
    Callback function invoked when a header name/value pair is received
    for the *frame*.  The *name* of length *namelen* is header name.
    The *value* of length *valuelen* is header value.  The *flags* is
    bitwise OR of one or more of :type:`nghttp2_nv_flag`.
    
    If :enum:`nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_INDEX` is set in
    *flags*, the receiver must not index this name/value pair when
    forwarding it to the next hop.  More specifically, "Literal Header
    Field never Indexed" representation must be used in HPACK encoding.
    
    When this callback is invoked, ``frame->hd.type`` is either
    :enum:`nghttp2_frame_type.NGHTTP2_HEADERS` or
    :enum:`nghttp2_frame_type.NGHTTP2_PUSH_PROMISE`.  After all header
    name/value pairs are processed with this callback, and no error has
    been detected, :type:`nghttp2_on_frame_recv_callback` will be
    invoked.  If there is an error in decompression,
    :type:`nghttp2_on_frame_recv_callback` for the *frame* will not be
    invoked.
    
    Both *name* and *value* are guaranteed to be NULL-terminated.  The
    *namelen* and *valuelen* do not include terminal NULL.  If
    `nghttp2_option_set_no_http_messaging()` is used with nonzero
    value, NULL character may be included in *name* or *value* before
    terminating NULL.
    
    Please note that unless `nghttp2_option_set_no_http_messaging()` is
    used, nghttp2 library does perform validation against the *name*
    and the *value* using `nghttp2_check_header_name()` and
    `nghttp2_check_header_value()`.  In addition to this, nghttp2
    performs validation based on HTTP Messaging rule, which is briefly
    explained in :ref:`http-messaging` section.
    
    If the application uses `nghttp2_session_mem_recv2()`, it can
    return :enum:`nghttp2_error.NGHTTP2_ERR_PAUSE` to make
    `nghttp2_session_mem_recv2()` return without processing further
    input bytes.  The memory pointed by *frame*, *name* and *value*
    parameters are retained until `nghttp2_session_mem_recv2()` or
    `nghttp2_session_recv()` is called.  The application must retain
    the input bytes which was used to produce these parameters, because
    it may refer to the memory region included in the input bytes.
    
    Returning
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE` will
    close the stream (promised stream if frame is PUSH_PROMISE) by
    issuing RST_STREAM with
    :enum:`nghttp2_error_code.NGHTTP2_INTERNAL_ERROR`.  In this case,
    :type:`nghttp2_on_header_callback` and
    :type:`nghttp2_on_frame_recv_callback` will not be invoked.  If a
    different error code is desirable, use
    `nghttp2_submit_rst_stream()` with a desired error code and then
    return :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.
    Again, use ``frame->push_promise.promised_stream_id`` as stream_id
    parameter in `nghttp2_submit_rst_stream()` if frame is
    PUSH_PROMISE.
    
    The implementation of this function must return 0 if it succeeds.
    It may return :enum:`nghttp2_error.NGHTTP2_ERR_PAUSE` or
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  For
    other critical failures, it must return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  If the other
    nonzero value is returned, it is treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  If
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` is returned,
    `nghttp2_session_recv()` and `nghttp2_session_mem_recv2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_on_header_callback()`.
    
    .. warning::
    
      Application should properly limit the total buffer size to store
      incoming header fields.  Without it, peer may send large number
      of header fields or large header fields to cause out of memory in
      local endpoint.  Due to how HPACK works, peer can do this
      effectively without using much memory on their own.
.. type:: int (*nghttp2_on_header_callback2)(nghttp2_session *session, const nghttp2_frame *frame, nghttp2_rcbuf *name, nghttp2_rcbuf *value, uint8_t flags, void *user_data)

    
    Callback function invoked when a header name/value pair is received
    for the *frame*.  The *name* is header name.  The *value* is header
    value.  The *flags* is bitwise OR of one or more of
    :type:`nghttp2_nv_flag`.
    
    This callback behaves like :type:`nghttp2_on_header_callback`,
    except that *name* and *value* are stored in reference counted
    buffer.  If application wishes to keep these references without
    copying them, use `nghttp2_rcbuf_incref()` to increment their
    reference count.  It is the application's responsibility to call
    `nghttp2_rcbuf_decref()` if they called `nghttp2_rcbuf_incref()` so
    as not to leak memory.  If the *session* is created by
    `nghttp2_session_server_new3()` or `nghttp2_session_client_new3()`,
    the function to free memory is the one belongs to the mem
    parameter.  As long as this free function alives, *name* and
    *value* can live after *session* was destroyed.
.. type:: int (*nghttp2_on_invalid_header_callback)( nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)

    
    Callback function invoked when a invalid header name/value pair is
    received for the *frame*.
    
    The parameter and behaviour are similar to
    :type:`nghttp2_on_header_callback`.  The difference is that this
    callback is only invoked when a invalid header name/value pair is
    received which is treated as stream error if this callback is not
    set.  Only invalid regular header field are passed to this
    callback.  In other words, invalid pseudo header field is not
    passed to this callback.  Also header fields which includes upper
    cased latter are also treated as error without passing them to this
    callback.
    
    This callback is only considered if HTTP messaging validation is
    turned on (which is on by default, see
    `nghttp2_option_set_no_http_messaging()`).
    
    With this callback, application inspects the incoming invalid
    field, and it also can reset stream from this callback by returning
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  By
    default, the error code is
    :enum:`nghttp2_error_code.NGHTTP2_PROTOCOL_ERROR`.  To change the
    error code, call `nghttp2_submit_rst_stream()` with the error code
    of choice in addition to returning
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.
    
    If 0 is returned, the header field is ignored, and the stream is
    not reset.
.. type:: int (*nghttp2_on_invalid_header_callback2)( nghttp2_session *session, const nghttp2_frame *frame, nghttp2_rcbuf *name, nghttp2_rcbuf *value, uint8_t flags, void *user_data)

    
    Callback function invoked when a invalid header name/value pair is
    received for the *frame*.
    
    The parameter and behaviour are similar to
    :type:`nghttp2_on_header_callback2`.  The difference is that this
    callback is only invoked when a invalid header name/value pair is
    received which is silently ignored if this callback is not set.
    Only invalid regular header field are passed to this callback.  In
    other words, invalid pseudo header field is not passed to this
    callback.  Also header fields which includes upper cased latter are
    also treated as error without passing them to this callback.
    
    This callback is only considered if HTTP messaging validation is
    turned on (which is on by default, see
    `nghttp2_option_set_no_http_messaging()`).
    
    With this callback, application inspects the incoming invalid
    field, and it also can reset stream from this callback by returning
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  By
    default, the error code is
    :enum:`nghttp2_error_code.NGHTTP2_INTERNAL_ERROR`.  To change the
    error code, call `nghttp2_submit_rst_stream()` with the error code
    of choice in addition to returning
    :enum:`nghttp2_error.NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.
.. type:: ssize_t (*nghttp2_select_padding_callback)(nghttp2_session *session, const nghttp2_frame *frame, size_t max_payloadlen, void *user_data)

    
    .. warning::
    
      Deprecated.  Use :type:`nghttp2_select_padding_callback2`
      instead.
    
    Callback function invoked when the library asks application how
    many padding bytes are required for the transmission of the
    *frame*.  The application must choose the total length of payload
    including padded bytes in range [frame->hd.length, max_payloadlen],
    inclusive.  Choosing number not in this range will be treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  Returning
    ``frame->hd.length`` means no padding is added.  Returning
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` will make
    `nghttp2_session_send()` and `nghttp2_session_mem_send()` functions
    immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_select_padding_callback()`.
.. type:: nghttp2_ssize (*nghttp2_select_padding_callback2)( nghttp2_session *session, const nghttp2_frame *frame, size_t max_payloadlen, void *user_data)

    
    Callback function invoked when the library asks application how
    many padding bytes are required for the transmission of the
    *frame*.  The application must choose the total length of payload
    including padded bytes in range [frame->hd.length, max_payloadlen],
    inclusive.  Choosing number not in this range will be treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  Returning
    ``frame->hd.length`` means no padding is added.  Returning
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` will make
    `nghttp2_session_send()` and `nghttp2_session_mem_send2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_select_padding_callback2()`.
.. type:: ssize_t (*nghttp2_data_source_read_length_callback)( nghttp2_session *session, uint8_t frame_type, int32_t stream_id, int32_t session_remote_window_size, int32_t stream_remote_window_size, uint32_t remote_max_frame_size, void *user_data)

    
    .. warning::
    
      Deprecated.  Use
      :type:`nghttp2_data_source_read_length_callback2` instead.
    
    Callback function invoked when library wants to get max length of
    data to send data to the remote peer.  The implementation of this
    function should return a value in the following range.  [1,
    min(*session_remote_window_size*, *stream_remote_window_size*,
    *remote_max_frame_size*)].  If a value greater than this range is
    returned than the max allow value will be used.  Returning a value
    smaller than this range is treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  The
    *frame_type* is provided for future extensibility and identifies
    the type of frame (see :type:`nghttp2_frame_type`) for which to get
    the length for.  Currently supported frame types are:
    :enum:`nghttp2_frame_type.NGHTTP2_DATA`.
    
    This callback can be used to control the length in bytes for which
    :type:`nghttp2_data_source_read_callback` is allowed to send to the
    remote endpoint.  This callback is optional.  Returning
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` will signal the
    entire session failure.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_data_source_read_length_callback()`.
.. type:: nghttp2_ssize (*nghttp2_data_source_read_length_callback2)( nghttp2_session *session, uint8_t frame_type, int32_t stream_id, int32_t session_remote_window_size, int32_t stream_remote_window_size, uint32_t remote_max_frame_size, void *user_data)

    
    Callback function invoked when library wants to get max length of
    data to send data to the remote peer.  The implementation of this
    function should return a value in the following range.  [1,
    min(*session_remote_window_size*, *stream_remote_window_size*,
    *remote_max_frame_size*)].  If a value greater than this range is
    returned than the max allow value will be used.  Returning a value
    smaller than this range is treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  The
    *frame_type* is provided for future extensibility and identifies
    the type of frame (see :type:`nghttp2_frame_type`) for which to get
    the length for.  Currently supported frame types are:
    :enum:`nghttp2_frame_type.NGHTTP2_DATA`.
    
    This callback can be used to control the length in bytes for which
    :type:`nghttp2_data_source_read_callback` is allowed to send to the
    remote endpoint.  This callback is optional.  Returning
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE` will signal the
    entire session failure.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_data_source_read_length_callback2()`.
.. type:: int (*nghttp2_on_begin_frame_callback)(nghttp2_session *session, const nghttp2_frame_hd *hd, void *user_data)

    
    Callback function invoked when a frame header is received.  The
    *hd* points to received frame header.
    
    Unlike :type:`nghttp2_on_frame_recv_callback`, this callback will
    also be called when frame header of CONTINUATION frame is received.
    
    If both :type:`nghttp2_on_begin_frame_callback` and
    :type:`nghttp2_on_begin_headers_callback` are set and HEADERS or
    PUSH_PROMISE is received, :type:`nghttp2_on_begin_frame_callback`
    will be called first.
    
    The implementation of this function must return 0 if it succeeds.
    If nonzero value is returned, it is treated as fatal error and
    `nghttp2_session_recv()` and `nghttp2_session_mem_recv2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    
    To set this callback to :type:`nghttp2_session_callbacks`, use
    `nghttp2_session_callbacks_set_on_begin_frame_callback()`.
.. type:: int (*nghttp2_on_extension_chunk_recv_callback)( nghttp2_session *session, const nghttp2_frame_hd *hd, const uint8_t *data, size_t len, void *user_data)

    
    Callback function invoked when chunk of extension frame payload is
    received.  The *hd* points to frame header.  The received
    chunk is *data* of length *len*.
    
    The implementation of this function must return 0 if it succeeds.
    
    To abort processing this extension frame, return
    :enum:`nghttp2_error.NGHTTP2_ERR_CANCEL`.
    
    If fatal error occurred, application should return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  In this case,
    `nghttp2_session_recv()` and `nghttp2_session_mem_recv2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  If the other
    values are returned, currently they are treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
.. type:: int (*nghttp2_unpack_extension_callback)(nghttp2_session *session, void **payload, const nghttp2_frame_hd *hd, void *user_data)

    
    Callback function invoked when library asks the application to
    unpack extension payload from its wire format.  The extension
    payload has been passed to the application using
    :type:`nghttp2_on_extension_chunk_recv_callback`.  The frame header
    is already unpacked by the library and provided as *hd*.
    
    To receive extension frames, the application must tell desired
    extension frame type to the library using
    `nghttp2_option_set_user_recv_extension_type()`.
    
    The implementation of this function may store the pointer to the
    created object as a result of unpacking in *\*payload*, and returns
    0.  The pointer stored in *\*payload* is opaque to the library, and
    the library does not own its pointer.  *\*payload* is initialized as
    ``NULL``.  The *\*payload* is available as ``frame->ext.payload`` in
    :type:`nghttp2_on_frame_recv_callback`.  Therefore if application
    can free that memory inside :type:`nghttp2_on_frame_recv_callback`
    callback.  Of course, application has a liberty not to use
    *\*payload*, and do its own mechanism to process extension frames.
    
    To abort processing this extension frame, return
    :enum:`nghttp2_error.NGHTTP2_ERR_CANCEL`.
    
    If fatal error occurred, application should return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  In this case,
    `nghttp2_session_recv()` and `nghttp2_session_mem_recv2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  If the other
    values are returned, currently they are treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
.. type:: ssize_t (*nghttp2_pack_extension_callback)(nghttp2_session *session, uint8_t *buf, size_t len, const nghttp2_frame *frame, void *user_data)

    
    .. warning::
    
      Deprecated.  Use :type:`nghttp2_pack_extension_callback2`
      instead.
    
    Callback function invoked when library asks the application to pack
    extension payload in its wire format.  The frame header will be
    packed by library.  Application must pack payload only.
    ``frame->ext.payload`` is the object passed to
    `nghttp2_submit_extension()` as payload parameter.  Application
    must pack extension payload to the *buf* of its capacity *len*
    bytes.  The *len* is at least 16KiB.
    
    The implementation of this function should return the number of
    bytes written into *buf* when it succeeds.
    
    To abort processing this extension frame, return
    :enum:`nghttp2_error.NGHTTP2_ERR_CANCEL`, and
    :type:`nghttp2_on_frame_not_send_callback` will be invoked.
    
    If fatal error occurred, application should return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  In this case,
    `nghttp2_session_send()` and `nghttp2_session_mem_send()` functions
    immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  If the other
    values are returned, currently they are treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  If the return
    value is strictly larger than *len*, it is treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
.. type:: nghttp2_ssize (*nghttp2_pack_extension_callback2)( nghttp2_session *session, uint8_t *buf, size_t len, const nghttp2_frame *frame, void *user_data)

    
    Callback function invoked when library asks the application to pack
    extension payload in its wire format.  The frame header will be
    packed by library.  Application must pack payload only.
    ``frame->ext.payload`` is the object passed to
    `nghttp2_submit_extension()` as payload parameter.  Application
    must pack extension payload to the *buf* of its capacity *len*
    bytes.  The *len* is at least 16KiB.
    
    The implementation of this function should return the number of
    bytes written into *buf* when it succeeds.
    
    To abort processing this extension frame, return
    :enum:`nghttp2_error.NGHTTP2_ERR_CANCEL`, and
    :type:`nghttp2_on_frame_not_send_callback` will be invoked.
    
    If fatal error occurred, application should return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  In this case,
    `nghttp2_session_send()` and `nghttp2_session_mem_send2()`
    functions immediately return
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  If the other
    values are returned, currently they are treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  If the return
    value is strictly larger than *len*, it is treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
.. type:: int (*nghttp2_error_callback)(nghttp2_session *session, const char *msg, size_t len, void *user_data)

    
    .. warning::
    
      Deprecated.  Use :type:`nghttp2_error_callback2` instead.
    
    Callback function invoked when library provides the error message
    intended for human consumption.  This callback is solely for
    debugging purpose.  The *msg* is typically NULL-terminated string
    of length *len*.  *len* does not include the sentinel NULL
    character.
    
    The format of error message may change between nghttp2 library
    versions.  The application should not depend on the particular
    format.
    
    Normally, application should return 0 from this callback.  If fatal
    error occurred while doing something in this callback, application
    should return :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    In this case, library will return immediately with return value
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  Currently, if
    nonzero value is returned from this callback, they are treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`, but application
    should not rely on this details.
.. type:: int (*nghttp2_error_callback2)(nghttp2_session *session, int lib_error_code, const char *msg, size_t len, void *user_data)

    
    Callback function invoked when library provides the error code, and
    message.  This callback is solely for debugging purpose.
    *lib_error_code* is one of error code defined in
    :enum:`nghttp2_error`.  The *msg* is typically NULL-terminated
    string of length *len*, and intended for human consumption.  *len*
    does not include the sentinel NULL character.
    
    The format of error message may change between nghttp2 library
    versions.  The application should not depend on the particular
    format.
    
    Normally, application should return 0 from this callback.  If fatal
    error occurred while doing something in this callback, application
    should return :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.
    In this case, library will return immediately with return value
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`.  Currently, if
    nonzero value is returned from this callback, they are treated as
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`, but application
    should not rely on this details.
.. type:: nghttp2_session_callbacks

    
    Callback functions for :type:`nghttp2_session`.  The details of
    this structure are intentionally hidden from the public API.


.. type:: void *(*nghttp2_malloc)(size_t size, void *mem_user_data)

    
    Custom memory allocator to replace malloc().  The *mem_user_data*
    is the mem_user_data member of :type:`nghttp2_mem` structure.
.. type:: void (*nghttp2_free)(void *ptr, void *mem_user_data)

    
    Custom memory allocator to replace free().  The *mem_user_data* is
    the mem_user_data member of :type:`nghttp2_mem` structure.
.. type:: void *(*nghttp2_calloc)(size_t nmemb, size_t size, void *mem_user_data)

    
    Custom memory allocator to replace calloc().  The *mem_user_data*
    is the mem_user_data member of :type:`nghttp2_mem` structure.
.. type:: void *(*nghttp2_realloc)(void *ptr, size_t size, void *mem_user_data)

    
    Custom memory allocator to replace realloc().  The *mem_user_data*
    is the mem_user_data member of :type:`nghttp2_mem` structure.
.. type:: nghttp2_mem

    
    Custom memory allocator functions and user defined pointer.  The
    *mem_user_data* member is passed to each allocator function.  This
    can be used, for example, to achieve per-session memory pool.
    
    In the following example code, ``my_malloc``, ``my_free``,
    ``my_calloc`` and ``my_realloc`` are the replacement of the
    standard allocators ``malloc``, ``free``, ``calloc`` and
    ``realloc`` respectively::
    
        void *my_malloc_cb(size_t size, void *mem_user_data) {
          return my_malloc(size);
        }
    
        void my_free_cb(void *ptr, void *mem_user_data) { my_free(ptr); }
    
        void *my_calloc_cb(size_t nmemb, size_t size, void *mem_user_data) {
          return my_calloc(nmemb, size);
        }
    
        void *my_realloc_cb(void *ptr, size_t size, void *mem_user_data) {
          return my_realloc(ptr, size);
        }
    
        void session_new() {
          nghttp2_session *session;
          nghttp2_session_callbacks *callbacks;
          nghttp2_mem mem = {NULL, my_malloc_cb, my_free_cb, my_calloc_cb,
                             my_realloc_cb};
    
          ...
    
          nghttp2_session_client_new3(&session, callbacks, NULL, NULL, &mem);
    
          ...
        }

    .. member::   void *mem_user_data

        An arbitrary user supplied data.  This is passed to each
        allocator function.
    .. member::   nghttp2_malloc malloc

        Custom allocator function to replace malloc().
    .. member::   nghttp2_free free

        Custom allocator function to replace free().
    .. member::   nghttp2_calloc calloc

        Custom allocator function to replace calloc().
    .. member::   nghttp2_realloc realloc

        Custom allocator function to replace realloc().

.. type:: nghttp2_option

    
    Configuration options for :type:`nghttp2_session`.  The details of
    this structure are intentionally hidden from the public API.


.. type:: nghttp2_extpri

    
    :type:`nghttp2_extpri` is :rfc:`9218` extensible priorities
    specification for a stream.

    .. member::   uint32_t urgency

        :member:`urgency` is the urgency of a stream, it must be in
        [:macro:`NGHTTP2_EXTPRI_URGENCY_HIGH`,
        :macro:`NGHTTP2_EXTPRI_URGENCY_LOW`], inclusive, and 0 is the
        highest urgency.
    .. member::   int inc

        :member:`inc` indicates that a content can be processed
        incrementally or not.  If inc is 0, it cannot be processed
        incrementally.  If inc is 1, it can be processed incrementally.
        Other value is not permitted.

.. type:: nghttp2_ext_altsvc

    
    The payload of ALTSVC frame.  ALTSVC frame is a non-critical
    extension to HTTP/2.  If this frame is received, and
    `nghttp2_option_set_user_recv_extension_type()` is not set, and
    `nghttp2_option_set_builtin_recv_extension_type()` is set for
    :enum:`nghttp2_frame_type.NGHTTP2_ALTSVC`,
    ``nghttp2_extension.payload`` will point to this struct.
    
    It has the following members:

    .. member::   uint8_t *origin

        The pointer to origin which this alternative service is
        associated with.  This is not necessarily NULL-terminated.
    .. member::   size_t origin_len

        The length of the *origin*.
    .. member::   uint8_t *field_value

        The pointer to Alt-Svc field value contained in ALTSVC frame.
        This is not necessarily NULL-terminated.
    .. member::   size_t field_value_len

        The length of the *field_value*.

.. type:: nghttp2_origin_entry

    
    The single entry of an origin.

    .. member::   uint8_t *origin

        The pointer to origin.  No validation is made against this field
        by the library.  This is not necessarily NULL-terminated.
    .. member::   size_t origin_len

        The length of the *origin*.

.. type:: nghttp2_ext_origin

    
    The payload of ORIGIN frame.  ORIGIN frame is a non-critical
    extension to HTTP/2 and defined by `RFC 8336
    <https://tools.ietf.org/html/rfc8336>`_.
    
    If this frame is received, and
    `nghttp2_option_set_user_recv_extension_type()` is not set, and
    `nghttp2_option_set_builtin_recv_extension_type()` is set for
    :enum:`nghttp2_frame_type.NGHTTP2_ORIGIN`,
    ``nghttp2_extension.payload`` will point to this struct.
    
    It has the following members:

    .. member::   size_t nov

        The number of origins contained in *ov*.
    .. member::   nghttp2_origin_entry *ov

        The pointer to the array of origins contained in ORIGIN frame.

.. type:: nghttp2_ext_priority_update

    
    The payload of PRIORITY_UPDATE frame.  PRIORITY_UPDATE frame is a
    non-critical extension to HTTP/2.  If this frame is received, and
    `nghttp2_option_set_user_recv_extension_type()` is not set, and
    `nghttp2_option_set_builtin_recv_extension_type()` is set for
    :enum:`nghttp2_frame_type.NGHTTP2_PRIORITY_UPDATE`,
    ``nghttp2_extension.payload`` will point to this struct.
    
    It has the following members:

    .. member::   int32_t stream_id

        The stream ID of the stream whose priority is updated.
    .. member::   uint8_t *field_value

        The pointer to Priority field value.  It is not necessarily
        NULL-terminated.
    .. member::   size_t field_value_len

        The length of the :member:`field_value`.

.. type:: nghttp2_hd_deflater

    
    HPACK deflater object.


.. type:: nghttp2_hd_inflater

    
    HPACK inflater object.


.. type:: nghttp2_stream

    
    The structure to represent HTTP/2 stream.  The details of this
    structure are intentionally hidden from the public API.


.. type:: void (*nghttp2_debug_vprintf_callback)(const char *format, va_list args)

    
    Callback function invoked when the library outputs debug logging.
    The function is called with arguments suitable for ``vfprintf(3)``
    
    The debug output is only enabled if the library is built with
    ``DEBUGBUILD`` macro defined.
