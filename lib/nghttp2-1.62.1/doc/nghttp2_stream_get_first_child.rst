
nghttp2_stream_get_first_child
==============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: nghttp2_stream * nghttp2_stream_get_first_child(nghttp2_stream *stream)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.  In the future release after the end of
      2024, this function will always return NULL.
    
    Returns the first child stream of *stream* in dependency tree.
    Returns NULL if there is no such stream.
