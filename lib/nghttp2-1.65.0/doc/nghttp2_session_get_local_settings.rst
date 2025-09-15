
nghttp2_session_get_local_settings
==================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: uint32_t nghttp2_session_get_local_settings( nghttp2_session *session, nghttp2_settings_id id)

    
    Returns the value of SETTINGS *id* of local endpoint acknowledged
    by the remote endpoint.  The *id* must be one of the values defined
    in :enum:`nghttp2_settings_id`.
