# Import declarations from libmonkey.h
# Used for the python API implementation

cdef extern from "libmonkey.h":
    cdef struct mklib_ctx_t:
        pass
    cdef enum mklib_cb:
        MKCB_IPCHECK = 1
        MKCB_URLCHECK
        MKCB_DATA
        MKCB_CLOSE
    cdef enum mklib_mkc:
        MKC_WORKERS = 1
        MKC_TIMEOUT
        MKC_USERDIR
        MKC_INDEXFILE
        MKC_HIDEVERSION
        MKC_RESUME
        MKC_KEEPALIVE
        MKC_KEEPALIVETIMEOUT
        MKC_MAXKEEPALIVEREQUEST
        MKC_MAXREQUESTSIZE
        MKC_SYMLINK
        MKC_DEFAULTMIMETYPE
    cdef struct mklib_vhost:
        pass
    cdef struct worker_info:
        pass
    cdef struct mklib_worker_info:
        unsigned long long accepted_connections
        unsigned long long closed_connections
        int pid
    cdef struct mklib_mime:
        char *name
        char *type

    ctypedef mklib_ctx_t *mklib_ctx
    ctypedef void mklib_session
    ctypedef int (*cb_ipcheck)(char *ip)
    ctypedef int (*cb_urlcheck)(char *ip)
    ctypedef int (*cb_data)(mklib_session *, char *vhost, char *url, char *get, unsigned long get_len, char *post, unsigned long post_len, unsigned int *status, char **content, unsigned long *clen, char *header)
    ctypedef int (*cb_close)(mklib_session *)

    mklib_ctx mklib_init(char *address, unsigned int port, unsigned int plugins, char *documentroot)
    int mklib_start(mklib_ctx)
    int mklib_stop(mklib_ctx)
    int mklib_config(mklib_ctx, ...)
    int mklib_get_config(mklib_ctx, ...)
    int mklib_callback_set(mklib_ctx, mklib_cb, void *)
    int mklib_vhost_config(mklib_ctx, char *)
    mklib_vhost **mklib_vhost_list(mklib_ctx)
    mklib_worker_info **mklib_scheduler_worker_info(mklib_ctx)
    void mklib_print_worker_info(mklib_worker_info *)
    int mklib_mimetype_add(mklib_ctx, char *, char *)
    mklib_mime **mklib_mimetype_list(mklib_ctx)
