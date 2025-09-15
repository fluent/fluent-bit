
nghttp2_nv_compare_name
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_nv_compare_name(const nghttp2_nv *lhs, const nghttp2_nv *rhs)

    
    Compares ``lhs->name`` of length ``lhs->namelen`` bytes and
    ``rhs->name`` of length ``rhs->namelen`` bytes.  Returns negative
    integer if ``lhs->name`` is found to be less than ``rhs->name``; or
    returns positive integer if ``lhs->name`` is found to be greater
    than ``rhs->name``; or returns 0 otherwise.
