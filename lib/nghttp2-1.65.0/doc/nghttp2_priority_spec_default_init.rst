
nghttp2_priority_spec_default_init
==================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_priority_spec_default_init(nghttp2_priority_spec *pri_spec)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.
    
    Initializes *pri_spec* with the default values.  The default values
    are: stream_id = 0, weight = :macro:`NGHTTP2_DEFAULT_WEIGHT` and
    exclusive = 0.
