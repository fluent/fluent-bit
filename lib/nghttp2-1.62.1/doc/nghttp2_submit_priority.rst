
nghttp2_submit_priority
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_priority(nghttp2_session *session, uint8_t flags, int32_t stream_id, const nghttp2_priority_spec *pri_spec)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.  In the future release after the end of
      2024, this function will always return 0 without doing anything.
    
    Submits PRIORITY frame to change the priority of stream *stream_id*
    to the priority specification *pri_spec*.
    
    The *flags* is currently ignored and should be
    :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    The *pri_spec* is a deprecated priority specification of this
    request.  ``NULL`` is not allowed for this function. To specify the
    priority, use `nghttp2_priority_spec_init()`.  This function will
    copy its data members.
    
    The ``pri_spec->weight`` must be in [:macro:`NGHTTP2_MIN_WEIGHT`,
    :macro:`NGHTTP2_MAX_WEIGHT`], inclusive.  If ``pri_spec->weight``
    is strictly less than :macro:`NGHTTP2_MIN_WEIGHT`, it becomes
    :macro:`NGHTTP2_MIN_WEIGHT`.  If it is strictly greater than
    :macro:`NGHTTP2_MAX_WEIGHT`, it becomes
    :macro:`NGHTTP2_MAX_WEIGHT`.
    
    If
    :enum:`nghttp2_settings_id.NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES`
    of value of 1 is received by a remote endpoint, this function does
    nothing and returns 0.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *stream_id* is 0; or the *pri_spec* is NULL; or trying to
        depend on itself.
