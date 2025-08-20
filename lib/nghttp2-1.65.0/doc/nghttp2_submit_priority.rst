
nghttp2_submit_priority
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_priority(nghttp2_session *session, uint8_t flags, int32_t stream_id, const nghttp2_priority_spec *pri_spec)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.
    
    This function is noop.  It always returns 0.
