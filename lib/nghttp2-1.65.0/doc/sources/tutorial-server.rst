Tutorial: HTTP/2 server
=========================

In this tutorial, we are going to write a single-threaded, event-based
HTTP/2 web server, which supports HTTPS only. It can handle concurrent
multiple requests, but only the GET method is supported. The complete
source code, `libevent-server.c`_, is attached at the end of this
page.  The source also resides in the examples directory in the
archive or repository.

This simple server takes 3 arguments: The port number to listen on,
the path to your SSL/TLS private key file, and the path to your
certificate file.  The synopsis is:

.. code-block:: text

    $ libevent-server PORT /path/to/server.key /path/to/server.crt

We use libevent in this tutorial to handle networking I/O.  Please
note that nghttp2 itself does not depend on libevent.

The server starts with some libevent and OpenSSL setup in the
``main()`` and ``run()`` functions. This setup isn't specific to
nghttp2, but one thing you should look at is setup of ALPN callback.
The ALPN callback is used by the server to select application
protocols offered by client.  In ALPN, client sends the list of
supported application protocols, and server selects one of them.  We
provide the callback for it::

    static int alpn_select_proto_cb(SSL *ssl _U_, const unsigned char **out,
                                    unsigned char *outlen, const unsigned char *in,
                                    unsigned int inlen, void *arg _U_) {
      int rv;

      rv = nghttp2_select_alpn(out, outlen, in, inlen);

      if (rv != 1) {
        return SSL_TLSEXT_ERR_NOACK;
      }

      return SSL_TLSEXT_ERR_OK;
    }

    static SSL_CTX *create_ssl_ctx(const char *key_file, const char *cert_file) {
      SSL_CTX *ssl_ctx;
      EC_KEY *ecdh;

      ssl_ctx = SSL_CTX_new(SSLv23_server_method());

      ...

      SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, NULL);

      return ssl_ctx;
    }

In ``alpn_select_proto_cb()``, we use `nghttp2_select_alpn()` to
select application protocol.  The `nghttp2_select_alpn()` returns 1
only if it selected h2 (ALPN identifier for HTTP/2), and out
parameters were assigned accordingly.

Next, let's take a look at the main structures used by the example
application:

We use the ``app_context`` structure to store application-wide data::

    struct app_context {
      SSL_CTX *ssl_ctx;
      struct event_base *evbase;
    };

We use the ``http2_session_data`` structure to store session-level
(which corresponds to one HTTP/2 connection) data::

    typedef struct http2_session_data {
      struct http2_stream_data root;
      struct bufferevent *bev;
      app_context *app_ctx;
      nghttp2_session *session;
      char *client_addr;
    } http2_session_data;

We use the ``http2_stream_data`` structure to store stream-level data::

    typedef struct http2_stream_data {
      struct http2_stream_data *prev, *next;
      char *request_path;
      int32_t stream_id;
      int fd;
    } http2_stream_data;

A single HTTP/2 session can have multiple streams.  To manage them, we
use a doubly linked list:  The first element of this list is pointed
to by the ``root->next`` in ``http2_session_data``.  Initially,
``root->next`` is ``NULL``.

libevent's bufferevent structure is used to perform network I/O, with
the pointer to the bufferevent stored in the ``http2_session_data``
structure.  Note that the bufferevent object is kept in
``http2_session_data`` and not in ``http2_stream_data``. This is
because ``http2_stream_data`` is just a logical stream multiplexed
over the single connection managed by the bufferevent in
``http2_session_data``.

We first create a listener object to accept incoming connections.
libevent's ``struct evconnlistener`` is used for this purpose::

    static void start_listen(struct event_base *evbase, const char *service,
                             app_context *app_ctx) {
      int rv;
      struct addrinfo hints;
      struct addrinfo *res, *rp;

      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_PASSIVE;
    #ifdef AI_ADDRCONFIG
      hints.ai_flags |= AI_ADDRCONFIG;
    #endif /* AI_ADDRCONFIG */

      rv = getaddrinfo(NULL, service, &hints, &res);
      if (rv != 0) {
        errx(1, NULL);
      }
      for (rp = res; rp; rp = rp->ai_next) {
        struct evconnlistener *listener;
        listener = evconnlistener_new_bind(
            evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
            16, rp->ai_addr, (int)rp->ai_addrlen);
        if (listener) {
          freeaddrinfo(res);

          return;
        }
      }
      errx(1, "Could not start listener");
    }

We specify the ``acceptcb`` callback, which is called when a new connection is
accepted::

    static void acceptcb(struct evconnlistener *listener _U_, int fd,
                         struct sockaddr *addr, int addrlen, void *arg) {
      app_context *app_ctx = (app_context *)arg;
      http2_session_data *session_data;

      session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);

      bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);
    }

Here we create the ``http2_session_data`` object. The connection's
bufferevent is initialized at the same time. We specify three
callbacks for the bufferevent: ``readcb``, ``writecb``, and
``eventcb``.

The ``eventcb()`` callback is invoked by the libevent event loop when an event
(e.g. connection has been established, timeout, etc.) occurs on the
underlying network socket::

    static void eventcb(struct bufferevent *bev _U_, short events, void *ptr) {
      http2_session_data *session_data = (http2_session_data *)ptr;
      if (events & BEV_EVENT_CONNECTED) {
        const unsigned char *alpn = NULL;
        unsigned int alpnlen = 0;
        SSL *ssl;

        fprintf(stderr, "%s connected\n", session_data->client_addr);

        ssl = bufferevent_openssl_get_ssl(session_data->bev);

        SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);

        if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
          fprintf(stderr, "%s h2 is not negotiated\n", session_data->client_addr);
          delete_http2_session_data(session_data);
          return;
        }

        initialize_nghttp2_session(session_data);

        if (send_server_connection_header(session_data) != 0 ||
            session_send(session_data) != 0) {
          delete_http2_session_data(session_data);
          return;
        }

        return;
      }
      if (events & BEV_EVENT_EOF) {
        fprintf(stderr, "%s EOF\n", session_data->client_addr);
      } else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "%s network error\n", session_data->client_addr);
      } else if (events & BEV_EVENT_TIMEOUT) {
        fprintf(stderr, "%s timeout\n", session_data->client_addr);
      }
      delete_http2_session_data(session_data);
    }

Here we validate that HTTP/2 is negotiated, and if not, drop
connection.

For the ``BEV_EVENT_EOF``, ``BEV_EVENT_ERROR``, and
``BEV_EVENT_TIMEOUT`` events, we just simply tear down the connection.
The ``delete_http2_session_data()`` function destroys the
``http2_session_data`` object and its associated bufferevent member.
As a result, the underlying connection is closed.

The
``BEV_EVENT_CONNECTED`` event is invoked when SSL/TLS handshake has
completed successfully. After this we are ready to begin communicating
via HTTP/2.

The ``initialize_nghttp2_session()`` function initializes the nghttp2
session object and several callbacks::

    static void initialize_nghttp2_session(http2_session_data *session_data) {
      nghttp2_session_callbacks *callbacks;

      nghttp2_session_callbacks_new(&callbacks);

      nghttp2_session_callbacks_set_send_callback2(callbacks, send_callback);

      nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                           on_frame_recv_callback);

      nghttp2_session_callbacks_set_on_stream_close_callback(
          callbacks, on_stream_close_callback);

      nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                       on_header_callback);

      nghttp2_session_callbacks_set_on_begin_headers_callback(
          callbacks, on_begin_headers_callback);

      nghttp2_session_server_new(&session_data->session, callbacks, session_data);

      nghttp2_session_callbacks_del(callbacks);
    }

Since we are creating a server, we use `nghttp2_session_server_new()`
to initialize the nghttp2 session object.  We also setup 5 callbacks
for the nghttp2 session, these are explained later.

The server now begins by sending the server connection preface, which
always consists of a SETTINGS frame.
``send_server_connection_header()`` configures and submits it::

    static int send_server_connection_header(http2_session_data *session_data) {
      nghttp2_settings_entry iv[1] = {
          {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
      int rv;

      rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                                   ARRLEN(iv));
      if (rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
      }
      return 0;
    }

In the example SETTINGS frame we've set
SETTINGS_MAX_CONCURRENT_STREAMS to 100. `nghttp2_submit_settings()`
is used to queue the frame for transmission, but note it only queues
the frame for transmission, and doesn't actually send it. All
functions in the ``nghttp2_submit_*()`` family have this property. To
actually send the frame, `nghttp2_session_send()` should be used, as
described later.

Since bufferevent may buffer more than the first 24 bytes from the client, we
have to process them here since libevent won't invoke callback functions for
this pending data. To process the received data, we call the
``session_recv()`` function::

    static int session_recv(http2_session_data *session_data) {
      nghttp2_ssize readlen;
      struct evbuffer *input = bufferevent_get_input(session_data->bev);
      size_t datalen = evbuffer_get_length(input);
      unsigned char *data = evbuffer_pullup(input, -1);

      readlen = nghttp2_session_mem_recv2(session_data->session, data, datalen);
      if (readlen < 0) {
        warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
        return -1;
      }
      if (evbuffer_drain(input, (size_t)readlen) != 0) {
        warnx("Fatal error: evbuffer_drain failed");
        return -1;
      }
      if (session_send(session_data) != 0) {
        return -1;
      }
      return 0;
    }

In this function, we feed all unprocessed but already received data to
the nghttp2 session object using the `nghttp2_session_mem_recv2()`
function. The `nghttp2_session_mem_recv2()` function processes the
data and may both invoke the previously setup callbacks and also queue
outgoing frames. To send any pending outgoing frames, we immediately
call ``session_send()``.

The ``session_send()`` function is defined as follows::

    static int session_send(http2_session_data *session_data) {
      int rv;
      rv = nghttp2_session_send(session_data->session);
      if (rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
      }
      return 0;
    }

The `nghttp2_session_send()` function serializes the frame into wire
format and calls the ``send_callback()``, which is of type
:type:`nghttp2_send_callback2`.  The ``send_callback()`` is defined as
follows::

    static nghttp2_ssize send_callback(nghttp2_session *session _U_,
                                       const uint8_t *data, size_t length,
                                       int flags _U_, void *user_data) {
      http2_session_data *session_data = (http2_session_data *)user_data;
      struct bufferevent *bev = session_data->bev;
      /* Avoid excessive buffering in server side. */
      if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
          OUTPUT_WOULDBLOCK_THRESHOLD) {
        return NGHTTP2_ERR_WOULDBLOCK;
      }
      bufferevent_write(bev, data, length);
      return (nghttp2_ssize)length;
    }

Since we use bufferevent to abstract network I/O, we just write the
data to the bufferevent object. Note that `nghttp2_session_send()`
continues to write all frames queued so far. If we were writing the
data to a non-blocking socket directly using the ``write()`` system
call in the ``send_callback()``, we'd soon receive an  ``EAGAIN`` or
``EWOULDBLOCK`` error since sockets have a limited send buffer. If
that happens, it's possible to return :macro:`NGHTTP2_ERR_WOULDBLOCK`
to signal the nghttp2 library to stop sending further data. But here,
when writing to the bufferevent, we have to regulate the amount data
to buffered ourselves to avoid using huge amounts of memory. To
achieve this, we check the size of the output buffer and if it reaches
more than or equal to ``OUTPUT_WOULDBLOCK_THRESHOLD`` bytes, we stop
writing data and return :macro:`NGHTTP2_ERR_WOULDBLOCK`.

The next bufferevent callback is ``readcb()``, which is invoked when
data is available to read in the bufferevent input buffer::

    static void readcb(struct bufferevent *bev _U_, void *ptr) {
      http2_session_data *session_data = (http2_session_data *)ptr;
      if (session_recv(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
      }
    }

In this function, we just call ``session_recv()`` to process incoming
data.

The third bufferevent callback is ``writecb()``, which is invoked when all
data in the bufferevent output buffer has been sent::

    static void writecb(struct bufferevent *bev, void *ptr) {
      http2_session_data *session_data = (http2_session_data *)ptr;
      if (evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
        return;
      }
      if (nghttp2_session_want_read(session_data->session) == 0 &&
          nghttp2_session_want_write(session_data->session) == 0) {
        delete_http2_session_data(session_data);
        return;
      }
      if (session_send(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
      }
    }

First we check whether we should drop the connection or not. The
nghttp2 session object keeps track of reception and transmission of
GOAWAY frames and other error conditions as well. Using this
information, the nghttp2 session object can state whether the
connection should be dropped or not. More specifically, if both
`nghttp2_session_want_read()` and `nghttp2_session_want_write()`
return 0, the connection is no-longer required and can be closed.
Since we are using bufferevent and its deferred callback option, the
bufferevent output buffer may still contain pending data when the
``writecb()`` is called. To handle this, we check whether the output
buffer is empty or not. If all of these conditions are met, we drop
connection.

Otherwise, we call ``session_send()`` to process the pending output
data. Remember that in ``send_callback()``, we must not write all data to
bufferevent to avoid excessive buffering. We continue processing pending data
when the output buffer becomes empty.

We have already described the nghttp2 callback ``send_callback()``.  Let's
learn about the remaining nghttp2 callbacks setup in
``initialize_nghttp2_setup()`` function.

The ``on_begin_headers_callback()`` function is invoked when the reception of
a header block in HEADERS or PUSH_PROMISE frame is started::

    static int on_begin_headers_callback(nghttp2_session *session,
                                         const nghttp2_frame *frame,
                                         void *user_data) {
      http2_session_data *session_data = (http2_session_data *)user_data;
      http2_stream_data *stream_data;

      if (frame->hd.type != NGHTTP2_HEADERS ||
          frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
      }
      stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
      nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                           stream_data);
      return 0;
    }

We are only interested in the HEADERS frame in this function. Since
the HEADERS frame has several roles in the HTTP/2 protocol, we check
that it is a request HEADERS, which opens new stream. If the frame is
a request HEADERS, we create a ``http2_stream_data`` object to store
the stream related data. We associate the created
``http2_stream_data`` object with the stream in the nghttp2 session
object using `nghttp2_set_stream_user_data()`. The
``http2_stream_data`` object can later be easily retrieved from the
stream, without searching through the doubly linked list.

In this example server, we want to serve files relative to the current working
directory in which the program was invoked. Each header name/value pair is
emitted via ``on_header_callback`` function, which is called after
``on_begin_headers_callback()``::

    static int on_header_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, const uint8_t *name,
                                  size_t namelen, const uint8_t *value,
                                  size_t valuelen, uint8_t flags _U_,
                                  void *user_data _U_) {
      http2_stream_data *stream_data;
      const char PATH[] = ":path";
      switch (frame->hd.type) {
      case NGHTTP2_HEADERS:
        if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
          break;
        }
        stream_data =
            nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (!stream_data || stream_data->request_path) {
          break;
        }
        if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
          size_t j;
          for (j = 0; j < valuelen && value[j] != '?'; ++j)
            ;
          stream_data->request_path = percent_decode(value, j);
        }
        break;
      }
      return 0;
    }

We search for the ``:path`` header field among the request headers and
store the requested path in the ``http2_stream_data`` object. In this
example program, we ignore the ``:method`` header field and always
treat the request as a GET request.

The ``on_frame_recv_callback()`` function is invoked when a frame is
fully received::

    static int on_frame_recv_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame, void *user_data) {
      http2_session_data *session_data = (http2_session_data *)user_data;
      http2_stream_data *stream_data;
      switch (frame->hd.type) {
      case NGHTTP2_DATA:
      case NGHTTP2_HEADERS:
        /* Check that the client request has finished */
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
          stream_data =
              nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
          /* For DATA and HEADERS frame, this callback may be called after
             on_stream_close_callback. Check that stream still alive. */
          if (!stream_data) {
            return 0;
          }
          return on_request_recv(session, session_data, stream_data);
        }
        break;
      default:
        break;
      }
      return 0;
    }

First we retrieve the ``http2_stream_data`` object associated with the
stream in ``on_begin_headers_callback()`` using
`nghttp2_session_get_stream_user_data()`. If the requested path
cannot be served for some reason (e.g. file is not found), we send a
404 response using ``error_reply()``.  Otherwise, we open
the requested file and send its content. We send the header field
``:status`` as a single response header.

Sending the file content is performed by the ``send_response()`` function::

    static int send_response(nghttp2_session *session, int32_t stream_id,
                             nghttp2_nv *nva, size_t nvlen, int fd) {
      int rv;
      nghttp2_data_provider2 data_prd;
      data_prd.source.fd = fd;
      data_prd.read_callback = file_read_callback;

      rv = nghttp2_submit_response2(session, stream_id, nva, nvlen, &data_prd);
      if (rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
      }
      return 0;
    }

nghttp2 uses the :type:`nghttp2_data_provider2` structure to send the
entity body to the remote peer. The ``source`` member of this
structure is a union, which can be either a void pointer or an int
(which is intended to be used as file descriptor). In this example
server, we use it as a file descriptor. We also set the
``file_read_callback()`` callback function to read the contents of the
file::

    static nghttp2_ssize file_read_callback(nghttp2_session *session _U_,
                                            int32_t stream_id _U_, uint8_t *buf,
                                            size_t length, uint32_t *data_flags,
                                            nghttp2_data_source *source,
                                            void *user_data _U_) {
      int fd = source->fd;
      ssize_t r;
      while ((r = read(fd, buf, length)) == -1 && errno == EINTR)
        ;
      if (r == -1) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
      if (r == 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      }
      return (nghttp2_ssize)r;
    }

If an error occurs while reading the file, we return
:macro:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  This tells the
library to send RST_STREAM to the stream.  When all data has been
read, the :macro:`NGHTTP2_DATA_FLAG_EOF` flag is set to signal nghttp2
that we have finished reading the file.

The `nghttp2_submit_response2()` function is used to send the response
to the remote peer.

The ``on_stream_close_callback()`` function is invoked when the stream
is about to close::

    static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                        uint32_t error_code _U_, void *user_data) {
      http2_session_data *session_data = (http2_session_data *)user_data;
      http2_stream_data *stream_data;

      stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
      if (!stream_data) {
        return 0;
      }
      remove_stream(session_data, stream_data);
      delete_http2_stream_data(stream_data);
      return 0;
    }

Lastly, we destroy the ``http2_stream_data`` object in this function,
since the stream is about to close and we no longer need the object.
