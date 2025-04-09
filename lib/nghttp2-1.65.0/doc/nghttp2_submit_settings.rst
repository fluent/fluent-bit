
nghttp2_submit_settings
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_settings(nghttp2_session *session, uint8_t flags, const nghttp2_settings_entry *iv, size_t niv)

    
    Stores local settings and submits SETTINGS frame.  The *iv* is the
    pointer to the array of :type:`nghttp2_settings_entry`.  The *niv*
    indicates the number of :type:`nghttp2_settings_entry`.
    
    The *flags* is currently ignored and should be
    :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    This function does not take ownership of the *iv*.  This function
    copies all the elements in the *iv*.
    
    While updating individual stream's local window size, if the window
    size becomes strictly larger than NGHTTP2_MAX_WINDOW_SIZE,
    RST_STREAM is issued against such a stream.
    
    SETTINGS with :enum:`nghttp2_flag.NGHTTP2_FLAG_ACK` is
    automatically submitted by the library and application could not
    send it at its will.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *iv* contains invalid value (e.g., initial window size
        strictly greater than (1 << 31) - 1.
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
