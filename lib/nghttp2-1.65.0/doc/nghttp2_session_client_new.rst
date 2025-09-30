
nghttp2_session_client_new
==========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_client_new(nghttp2_session **session_ptr, const nghttp2_session_callbacks *callbacks, void *user_data)

    
    Initializes *\*session_ptr* for client use.  The all members of
    *callbacks* are copied to *\*session_ptr*.  Therefore *\*session_ptr*
    does not store *callbacks*.  The *user_data* is an arbitrary user
    supplied data, which will be passed to the callback functions.
    
    The :type:`nghttp2_send_callback2` must be specified.  If the
    application code uses `nghttp2_session_recv()`, the
    :type:`nghttp2_recv_callback` must be specified.  The other members
    of *callbacks* can be ``NULL``.
    
    If this function fails, *\*session_ptr* is left untouched.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
