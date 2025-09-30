
nghttp2_stream_get_parent
=========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: nghttp2_stream * nghttp2_stream_get_parent(nghttp2_stream *stream)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.
    
    This function always returns NULL.
