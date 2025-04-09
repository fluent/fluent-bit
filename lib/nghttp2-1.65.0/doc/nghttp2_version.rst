
nghttp2_version
===============

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: nghttp2_info *nghttp2_version(int least_version)

    
    Returns a pointer to a nghttp2_info struct with version information
    about the run-time library in use.  The *least_version* argument
    can be set to a 24 bit numerical value for the least accepted
    version number and if the condition is not met, this function will
    return a ``NULL``.  Pass in 0 to skip the version checking.
