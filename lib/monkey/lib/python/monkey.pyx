cimport monkey

cdef:
    void *c_cb_ipcheck_fn
    void *c_cb_data_fn
    void *c_cb_urlcheck_fn
    void *c_cb_close_fn
    monkey.mklib_ctx _server = NULL


cdef class Mimetype:
    """
    Store a name, type pair representing a mime
    """
    def __init__(self):
        self.name = ''
        self.type = ''


cdef class Worker:
    """
    Store information about a monkey worker thread.

    Call print_info to print the information.
    """
    cdef:
        mklib_worker_info *_worker
        unsigned long long accepted_connections
        unsigned long long closed_connections
        int pid
    def __init__(self):
        self.accepted_connections = 0
        self.closed_connections = 0
        self.pid = -1
    cdef _set(self, mklib_worker_info *worker):
        self._worker = worker
    def print_info(self):
        """
        Print current worker associated information.
        """
        monkey.mklib_print_worker_info(self._worker)


cdef int c_cb_ipcheck(char *ip) with gil:
    func = <object> c_cb_ipcheck_fn
    return func(ip)


cdef int c_cb_urlcheck(char *ip) with gil:
    func = <object> c_cb_urlcheck_fn
    return func(ip)


cdef int c_cb_data(mklib_session *session, char *vhost, char *url, char *get, unsigned long get_len, char *post, unsigned long post_len, unsigned int *status, char **content, unsigned long *clen, char *header) with gil:
    py_vhost = None if url == NULL else vhost
    py_url = None if url == NULL else url
    py_get = None if get == NULL else get
    py_post = None if post == NULL else post
    py_header = None if header == NULL else header
    func = <object> c_cb_data_fn
    ret = func(py_vhost, py_url, py_get, get_len, py_post, post_len, py_header)
    if 'content' in ret:
        content[0] = ret['content']
    if 'status' in ret:
        status[0] = ret['status']
    if 'content_len' in ret:
        clen[0] = ret['content_len']
    return ret['return']


cdef int c_cb_close(mklib_session *session) with gil:
    func = <object> c_cb_close_fn
    return func()


def init(address=None, int port=0, int plugins=0, documentroot=None):
    """
    Initialize the monkey server.

    Keyword arguments:
    address -- address to bind the server (default localhost)
    port -- listen on this port (default 0 - specified in configuration file)
    plugins -- plugins to load
    documentroot -- the directory to serve

    Return True if no error occured, else False.
    """
    global _server
    if address is None:
        if documentroot is None:
            _server = monkey.mklib_init(NULL, port, plugins, NULL)
        else:
            _server = monkey.mklib_init(NULL, port, plugins, documentroot)
    else:
        if documentroot is None:
            _server = monkey.mklib_init(address, port, plugins, NULL)
        else:
            _server = monkey.mklib_init(address, port, plugins, documentroot)
    if _server == NULL:
        return False
    return True


def start():
    """
    Start the monkey server.

    Return True if no error occured, else False.
    """

    return <bint>monkey.mklib_start(_server)


def stop():
    """
    Stop the monkey server.

    Return True if no error occured, else False.
    """

    return <bint>monkey.mklib_stop(_server)


def configure(**args):
    """
    Configure the monkey server. Call before starting the server.

    Keyword arguments:
    workers -- How many workers threads to spawn
    timeout -- How many seconds to wait for a response
    userdir -- What is the user's www space name
    indexfile -- the default index.html
    hideversion -- Whether to hide the libmonkey version in headers and error pages
    resume -- Whether to support resuming
    keepalive -- Whether to support keep-alives
    keepalive_timeout -- How many seconds to keep a keep-alive connection open
    max_keepalive_request -- How many keep-alive requests to handle at once
    max_request_size -- The maximum size of a request, in KiB
    symlink -- Whether to support symbolic links
    default_mimetype -- The default mimetype when the file has unknown extension

    Return True if configuration succeeded, else False.
    """
    cdef:
        int integer, ret = 0
        char *string
    for a in args:
        if a == 'workers':
            integer = args['workers']
            ret |= mklib_config(_server, MKC_WORKERS, integer, NULL)
        elif a == 'timeout':
            integer = args['timeout']
            ret |= mklib_config(_server, MKC_TIMEOUT, integer, NULL)
        elif a == 'userdir':
            string = args['userdir']
            ret |= mklib_config(_server, MKC_USERDIR, string, NULL)
        elif a == 'indexfile':
            string = args['indexfile']
            ret |= mklib_config(_server, MKC_INDEXFILE, string, NULL)
        elif a == 'hideversion':
            integer = args['hideversion']
            ret |= mklib_config(_server, MKC_HIDEVERSION, integer, NULL)
        elif a == 'resume':
            integer = args['resume']
            ret |= mklib_config(_server, MKC_RESUME, integer, NULL)
        elif a == 'keepalive':
            integer = args['keepalive']
            ret |= mklib_config(_server, MKC_KEEPALIVE, integer, NULL)
        elif a == 'keepalive_timeout':
            integer = args['keepalive_timeout']
            ret |= mklib_config(_server, MKC_KEEPALIVETIMEOUT, integer, NULL)
        elif a == 'max_keepalive_request':
            integer = args['max_keepalive_request']
            ret |= mklib_config(_server, MKC_MAXKEEPALIVEREQUEST, integer, NULL)
        elif a == 'max_request_size':
            integer = args['max_request_size']
            ret |= mklib_config(_server, MKC_MAXREQUESTSIZE, integer, NULL)
        elif a == 'symlink':
            integer = args['symlink']
            ret |= mklib_config(_server, MKC_SYMLINK, integer, NULL)
        elif a == 'default_mimetype':
            string = args['default_mimetype']
            ret |= mklib_config(_server, MKC_DEFAULTMIMETYPE, string, NULL)
    return <bint>ret


def getconfig():
    """
    Return the current server configuration as a dictionary.
    """
    cdef:
        int workers, timeout, resume, keepalive, keepalive_timeout, max_keepalive_request, max_request_size, symlink
        char userdir[1024]
        char default_mimetype[1024]
    ret = {}
    monkey.mklib_get_config(_server, MKC_WORKERS, &workers, MKC_TIMEOUT, &timeout, MKC_USERDIR, userdir, MKC_RESUME, &resume, MKC_KEEPALIVE, &keepalive, MKC_KEEPALIVETIMEOUT, &keepalive_timeout, MKC_MAXKEEPALIVEREQUEST, &max_keepalive_request, MKC_MAXREQUESTSIZE, &max_request_size, MKC_SYMLINK, &symlink, MKC_DEFAULTMIMETYPE, default_mimetype, NULL)
    ret['workers'] = workers
    ret['timeout'] = timeout
    ret['userdir'] = userdir
    ret['resume'] = resume
    ret['keepalive'] = keepalive
    ret['keepalive_timeout'] = keepalive_timeout
    ret['max_keepalive_request'] = max_keepalive_request
    ret['max_request_size'] = max_request_size
    ret['symlink'] = symlink
    ret['default_mimetype'] = default_mimetype

    return ret


def mimetype_list():
    """
    Return a list of mimetypes.
    """
    cdef:
        mklib_mime **mimetypes
        int i = 0
    ret = []
    mimetypes = monkey.mklib_mimetype_list(_server)
    while mimetypes[i] != NULL:
        mimetype = Mimetype()
        mimetype.name = mimetypes[i].name
        mimetype.type = mimetypes[i].type
        ret.append(mimetype)
        i += 1
    return ret


def mimetype_add(char *name, char *type):
    """
    Add a new mimetype.

    Arguments:
    name -- the file extension
    type -- the mime type, e.g. "text/html"

    Return True on success, False otherwise.
    """
    return mklib_mimetype_add(_server, name, type)


def set_callback(callback, func):
    """
    Set a user defined callback.

    Arguments:
    callback -- type of the callback
    func -- function passed as a callback

    Available callbacks:
    callback = 'ip'
        Called right after a new connection is established. The function receives the
        IP in text form. Return False to drop the connection.

        Function signature:
        def ipch(ip):

        Return True/False

    callback = 'url'
        Called when the URL is known. Check whether the URL is valid. Return
        False to drop the connection.

        Function signature:
        def urlcb(url):

        Return True/False

    callback = 'data'
        Called on a get/post request.

        Function signature:
        def datacb(vhost, url, get, get_len, post, post_len, header)

        Example return value: {'return': 1', 'content': html content,
            'content_len': length of set html content}

    callback = 'close'
        Called on closing connection.

        Function signature:

        def closecb():

    Return True on success, False otherwise.
    """

    if callback == 'data':
        global c_cb_data_fn
        c_cb_data_fn = <void *> func
        return mklib_callback_set(_server, MKCB_DATA, <void *> c_cb_data)
    if callback == 'ip':
        global c_cb_ipcheck_fn
        c_cb_ipcheck_fn = <void *> func
        return mklib_callback_set(_server, MKCB_IPCHECK, <void *> c_cb_ipcheck)
    if callback == 'url':
        global c_cb_urlcheck_fn
        c_cb_urlcheck_fn = <void *> func
        return mklib_callback_set(_server, MKCB_URLCHECK, <void *> c_cb_urlcheck)
    if callback == 'close':
        global c_cb_close_fn
        c_cb_close_fn = <void *> func
        return mklib_callback_set(_server, MKCB_CLOSE, <void *> c_cb_close)


def scheduler_workers_info():
    """
    Return a list of workers
    """
    cdef:
        mklib_worker_info **workers
        int i = 0
    ret = []
    workers = monkey.mklib_scheduler_worker_info(_server)
    while workers[i] != NULL:
        worker = Worker()
        worker._set(workers[i])
        worker.accepted_connections = workers[i].accepted_connections
        worker.closed_connections = workers[i].closed_connections
        worker.pid = workers[i].pid
        ret.append(worker)
        i += 1
    return ret
