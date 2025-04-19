
nghttp2_session_get_remote_settings
===================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: uint32_t nghttp2_session_get_remote_settings( nghttp2_session *session, nghttp2_settings_id id)

    
    Returns the value of SETTINGS *id* notified by a remote endpoint.
    The *id* must be one of values defined in
    :enum:`nghttp2_settings_id`.
