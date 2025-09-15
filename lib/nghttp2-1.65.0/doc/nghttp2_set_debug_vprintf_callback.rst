
nghttp2_set_debug_vprintf_callback
==================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_set_debug_vprintf_callback( nghttp2_debug_vprintf_callback debug_vprintf_callback)

    
    Sets a debug output callback called by the library when built with
    ``DEBUGBUILD`` macro defined.  If this option is not used, debug
    log is written into standard error output.
    
    For builds without ``DEBUGBUILD`` macro defined, this function is
    noop.
    
    Note that building with ``DEBUGBUILD`` may cause significant
    performance penalty to libnghttp2 because of extra processing.  It
    should be used for debugging purpose only.
    
    .. Warning::
    
      Building with ``DEBUGBUILD`` may cause significant performance
      penalty to libnghttp2 because of extra processing.  It should be
      used for debugging purpose only.  We write this two times because
      this is important.
