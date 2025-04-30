
nghttp2_strerror
================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: const char *nghttp2_strerror(int lib_error_code)

    
    Returns string describing the *lib_error_code*.  The
    *lib_error_code* must be one of the :enum:`nghttp2_error`.
