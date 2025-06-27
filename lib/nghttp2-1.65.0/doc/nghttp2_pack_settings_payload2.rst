
nghttp2_pack_settings_payload2
==============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: nghttp2_ssize nghttp2_pack_settings_payload2( uint8_t *buf, size_t buflen, const nghttp2_settings_entry *iv, size_t niv)

    
    Serializes the SETTINGS values *iv* in the *buf*.  The size of the
    *buf* is specified by *buflen*.  The number of entries in the *iv*
    array is given by *niv*.  The required space in *buf* for the *niv*
    entries is ``6*niv`` bytes and if the given buffer is too small, an
    error is returned.  This function is used mainly for creating a
    SETTINGS payload to be sent with the ``HTTP2-Settings`` header
    field in an HTTP Upgrade request.  The data written in *buf* is NOT
    base64url encoded and the application is responsible for encoding.
    
    This function returns the number of bytes written in *buf*, or one
    of the following negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *iv* contains duplicate settings ID or invalid value.
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INSUFF_BUFSIZE`
        The provided *buflen* size is too small to hold the output.
