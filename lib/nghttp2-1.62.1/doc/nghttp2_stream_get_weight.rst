
nghttp2_stream_get_weight
=========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_stream_get_weight(nghttp2_stream *stream)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.  In the future release after the end of
      2024, this function will always return
      :macro:`NGHTTP2_DEFAULT_WEIGHT`.
    
    Returns dependency weight to the parent stream of *stream*.
