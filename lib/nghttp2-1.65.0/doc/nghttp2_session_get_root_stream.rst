
nghttp2_session_get_root_stream
===============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: nghttp2_stream * nghttp2_session_get_root_stream(nghttp2_session *session)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.
    
    Returns root of dependency tree, which is imaginary stream with
    stream ID 0.  The returned pointer is valid until *session* is
    freed by `nghttp2_session_del()`.
