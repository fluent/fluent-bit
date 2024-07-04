
nghttp2_stream_get_sum_dependency_weight
========================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_stream_get_sum_dependency_weight(nghttp2_stream *stream)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.  In the future release after the end of
      2024, this function will always return 0.
    
    Returns the sum of the weight for *stream*'s children.
