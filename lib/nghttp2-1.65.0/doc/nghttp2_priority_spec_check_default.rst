
nghttp2_priority_spec_check_default
===================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_priority_spec_check_default(const nghttp2_priority_spec *pri_spec)

    
    .. warning::
    
      Deprecated.  :rfc:`7540` priorities are deprecated by
      :rfc:`9113`.  Consider migrating to :rfc:`9218` extensible
      prioritization scheme.
    
    Returns nonzero if the *pri_spec* is filled with default values.
