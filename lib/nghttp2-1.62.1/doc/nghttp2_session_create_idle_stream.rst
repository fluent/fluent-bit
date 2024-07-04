
nghttp2_session_create_idle_stream
==================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_create_idle_stream(nghttp2_session *session, int32_t stream_id, const nghttp2_priority_spec *pri_spec)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.  In the future release after the end of
      2024, this function will always return 0 without doing anything.
    
    Creates idle stream with the given *stream_id*, and priority
    *pri_spec*.
    
    The stream creation is done without sending PRIORITY frame, which
    means that peer does not know about the existence of this idle
    stream in the local endpoint.
    
    RFC 7540 does not disallow the use of creation of idle stream with
    odd or even stream ID regardless of client or server.  So this
    function can create odd or even stream ID regardless of client or
    server.  But probably it is a bit safer to use the stream ID the
    local endpoint can initiate (in other words, use odd stream ID for
    client, and even stream ID for server), to avoid potential
    collision from peer's instruction.  Also we can use
    `nghttp2_session_set_next_stream_id()` to avoid to open created
    idle streams accidentally if we follow this recommendation.
    
    If *session* is initialized as server, and ``pri_spec->stream_id``
    points to the idle stream, the idle stream is created if it does
    not exist.  The created idle stream will depend on root stream
    (stream 0) with weight 16.
    
    Otherwise, if stream denoted by ``pri_spec->stream_id`` is not
    found, we use default priority instead of given *pri_spec*.  That
    is make stream depend on root stream with weight 16.
    
    If
    :enum:`nghttp2_settings_id.NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES`
    of value of 1 is submitted via `nghttp2_submit_settings()`, this
    function does nothing and returns 0.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        Attempted to depend on itself; or stream denoted by *stream_id*
        already exists; or *stream_id* cannot be used to create idle
        stream (in other words, local endpoint has already opened
        stream ID greater than or equal to the given stream ID; or
        *stream_id* is 0
