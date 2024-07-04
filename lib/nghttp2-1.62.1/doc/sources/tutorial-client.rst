Tutorial: HTTP/2 client
=========================

In this tutorial, we are going to write a very primitive HTTP/2
client. The complete source code, `libevent-client.c`_, is attached at
the end of this page.  It also resides in the examples directory in
the archive or repository.

This simple client takes a single HTTPS URI and retrieves the resource
at the URI. The synopsis is:

.. code-block:: text

    $ libevent-client HTTPS_URI

We use libevent in this tutorial to handle networking I/O.  Please
note that nghttp2 itself does not depend on libevent.

The client starts with some libevent and OpenSSL setup in the
``main()`` and ``run()`` functions. This setup isn't specific to
nghttp2, but one thing you should look at is setup of ALPN.  Client
tells application protocols that it supports to server via ALPN::

    static SSL_CTX *create_ssl_ctx(void) {
      SSL_CTX *ssl_ctx;
      ssl_ctx = SSL_CTX_new(SSLv23_client_method());
      if (!ssl_ctx) {
        errx(1, "Could not create SSL/TLS context: %s",
             ERR_error_string(ERR_get_error(), NULL));
      }
      SSL_CTX_set_options(ssl_ctx,
                          SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                              SSL_OP_NO_COMPRESSION |
                              SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

      SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);

      return ssl_ctx;
    }

Here we see ``SSL_CTX_get_alpn_protos()`` function call.  We instructs
OpenSSL to notify the server that we support h2, ALPN identifier for
HTTP/2.

The example client defines a couple of structs:

We define and use a ``http2_session_data`` structure to store data
related to the HTTP/2 session::

    typedef struct {
      nghttp2_session *session;
      struct evdns_base *dnsbase;
      struct bufferevent *bev;
      http2_stream_data *stream_data;
    } http2_session_data;

Since this program only handles one URI, it uses only one stream. We
store the single stream's data in a ``http2_stream_data`` structure
and the ``stream_data`` points to it. The ``http2_stream_data``
structure is defined as follows::

    typedef struct {
      /* The NULL-terminated URI string to retrieve. */
      const char *uri;
      /* Parsed result of the |uri| */
      struct http_parser_url *u;
      /* The authority portion of the |uri|, not NULL-terminated */
      char *authority;
      /* The path portion of the |uri|, including query, not
         NULL-terminated */
      char *path;
      /* The length of the |authority| */
      size_t authoritylen;
      /* The length of the |path| */
      size_t pathlen;
      /* The stream ID of this stream */
      int32_t stream_id;
    } http2_stream_data;

We create and initialize these structures in
``create_http2_session_data()`` and ``create_http2_stream_data()``
respectively.

``initiate_connection()`` is called to start the connection to the
remote server. It's defined as::

    static void initiate_connection(struct event_base *evbase, SSL_CTX *ssl_ctx,
                                    const char *host, uint16_t port,
                                    http2_session_data *session_data) {
      int rv;
      struct bufferevent *bev;
      SSL *ssl;

      ssl = create_ssl(ssl_ctx);
      bev = bufferevent_openssl_socket_new(
          evbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
          BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);
      bufferevent_enable(bev, EV_READ | EV_WRITE);
      bufferevent_setcb(bev, readcb, writecb, eventcb, session_data);
      rv = bufferevent_socket_connect_hostname(bev, session_data->dnsbase,
                                               AF_UNSPEC, host, port);

      if (rv != 0) {
        errx(1, "Could not connect to the remote host %s", host);
      }
      session_data->bev = bev;
    }

``initiate_connection()`` creates a bufferevent for the connection and
sets up three callbacks: ``readcb``, ``writecb``, and ``eventcb``.

The ``eventcb()`` is invoked by the libevent event loop when an event
(e.g. connection has been established, timeout, etc.) occurs on the
underlying network socket::

    static void eventcb(struct bufferevent *bev, short events, void *ptr) {
      http2_session_data *session_data = (http2_session_data *)ptr;
      if (events & BEV_EVENT_CONNECTED) {
        int fd = bufferevent_getfd(bev);
        int val = 1;
        const unsigned char *alpn = NULL;
        unsigned int alpnlen = 0;
        SSL *ssl;

        fprintf(stderr, "Connected\n");

        ssl = bufferevent_openssl_get_ssl(session_data->bev);

        SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);

        if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
          fprintf(stderr, "h2 is not negotiated\n");
          delete_http2_session_data(session_data);
          return;
        }

        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
        initialize_nghttp2_session(session_data);
        send_client_connection_header(session_data);
        submit_request(session_data);
        if (session_send(session_data) != 0) {
          delete_http2_session_data(session_data);
        }
        return;
      }
      if (events & BEV_EVENT_EOF) {
        warnx("Disconnected from the remote host");
      } else if (events & BEV_EVENT_ERROR) {
        warnx("Network error");
      } else if (events & BEV_EVENT_TIMEOUT) {
        warnx("Timeout");
      }
      delete_http2_session_data(session_data);
    }

Here we validate that HTTP/2 is negotiated, and if not, drop
connection.

For ``BEV_EVENT_EOF``, ``BEV_EVENT_ERROR``, and ``BEV_EVENT_TIMEOUT``
events, we just simply tear down the connection.

The ``BEV_EVENT_CONNECTED`` event is invoked when the SSL/TLS
handshake has completed successfully. After this we're ready to begin
communicating via HTTP/2.

The ``initialize_nghttp2_session()`` function initializes the nghttp2
session object and several callbacks::

    static void initialize_nghttp2_session(http2_session_data *session_data) {
      nghttp2_session_callbacks *callbacks;

      nghttp2_session_callbacks_new(&callbacks);

      nghttp2_session_callbacks_set_send_callback2(callbacks, send_callback);

      nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                           on_frame_recv_callback);

      nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
          callbacks, on_data_chunk_recv_callback);

      nghttp2_session_callbacks_set_on_stream_close_callback(
          callbacks, on_stream_close_callback);

      nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                       on_header_callback);

      nghttp2_session_callbacks_set_on_begin_headers_callback(
          callbacks, on_begin_headers_callback);

      nghttp2_session_client_new(&session_data->session, callbacks, session_data);

      nghttp2_session_callbacks_del(callbacks);
    }

Since we are creating a client, we use `nghttp2_session_client_new()`
to initialize the nghttp2 session object.  The callbacks setup are
explained later.

The `delete_http2_session_data()` function destroys ``session_data``
and frees its bufferevent, so the underlying connection is closed. It
also calls `nghttp2_session_del()` to delete the nghttp2 session
object.

A HTTP/2 connection begins by sending the client connection preface,
which is a 24 byte magic byte string (:macro:`NGHTTP2_CLIENT_MAGIC`),
followed by a SETTINGS frame. The 24 byte magic string is sent
automatically by nghttp2. We send the SETTINGS frame in
``send_client_connection_header()``::

    static void send_client_connection_header(http2_session_data *session_data) {
      nghttp2_settings_entry iv[1] = {
          {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
      int rv;

      /* client 24 bytes magic string will be sent by nghttp2 library */
      rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                                   ARRLEN(iv));
      if (rv != 0) {
        errx(1, "Could not submit SETTINGS: %s", nghttp2_strerror(rv));
      }
    }

Here we specify SETTINGS_MAX_CONCURRENT_STREAMS as 100. This is not
needed for this tiny example program, it just demonstrates use of the
SETTINGS frame. To queue the SETTINGS frame for transmission, we call
`nghttp2_submit_settings()`. Note that `nghttp2_submit_settings()`
only queues the frame for transmission, and doesn't actually send it.
All ``nghttp2_submit_*()`` family functions have this property. To
actually send the frame, `nghttp2_session_send()` has to be called,
which is described (and called) later.

After the transmission of the client connection header, we enqueue the
HTTP request in the ``submit_request()`` function::

    static void submit_request(http2_session_data *session_data) {
      int32_t stream_id;
      http2_stream_data *stream_data = session_data->stream_data;
      const char *uri = stream_data->uri;
      const struct http_parser_url *u = stream_data->u;
      nghttp2_nv hdrs[] = {
          MAKE_NV2(":method", "GET"),
          MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],
                  u->field_data[UF_SCHEMA].len),
          MAKE_NV(":authority", stream_data->authority, stream_data->authoritylen),
          MAKE_NV(":path", stream_data->path, stream_data->pathlen)};
      fprintf(stderr, "Request headers:\n");
      print_headers(stderr, hdrs, ARRLEN(hdrs));
      stream_id = nghttp2_submit_request2(session_data->session, NULL, hdrs,
                                          ARRLEN(hdrs), NULL, stream_data);
      if (stream_id < 0) {
        errx(1, "Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
      }

      stream_data->stream_id = stream_id;
    }

We build the HTTP request header fields in ``hdrs``, which is an array
of :type:`nghttp2_nv`. There are four header fields to be sent:
``:method``, ``:scheme``, ``:authority``, and ``:path``. To queue the
HTTP request, we call `nghttp2_submit_request2()`. The ``stream_data``
is passed via the *stream_user_data* parameter, which is helpfully
later passed back to callback functions.

`nghttp2_submit_request2()` returns the newly assigned stream ID for
the request.

The next bufferevent callback is ``readcb()``, which is invoked when
data is available to read from the bufferevent input buffer::

    static void readcb(struct bufferevent *bev, void *ptr) {
      http2_session_data *session_data = (http2_session_data *)ptr;
      nghttp2_ssize readlen;
      struct evbuffer *input = bufferevent_get_input(bev);
      size_t datalen = evbuffer_get_length(input);
      unsigned char *data = evbuffer_pullup(input, -1);

      readlen = nghttp2_session_mem_recv2(session_data->session, data, datalen);
      if (readlen < 0) {
        warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
        delete_http2_session_data(session_data);
        return;
      }
      if (evbuffer_drain(input, (size_t)readlen) != 0) {
        warnx("Fatal error: evbuffer_drain failed");
        delete_http2_session_data(session_data);
        return;
      }
      if (session_send(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
      }
    }

In this function we feed all unprocessed, received data to the nghttp2
session object using the `nghttp2_session_mem_recv2()` function.
`nghttp2_session_mem_recv2()` processes the received data and may
invoke nghttp2 callbacks and queue frames for transmission.  Since
there may be pending frames for transmission, we call immediately
``session_send()`` to send them.  ``session_send()`` is defined as
follows::

    static int session_send(http2_session_data *session_data) {
      int rv;

      rv = nghttp2_session_send(session_data->session);
      if (rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
      }
      return 0;
    }

The `nghttp2_session_send()` function serializes pending frames into
wire format and calls the ``send_callback()`` function to send them.
``send_callback()`` has type :type:`nghttp2_send_callback2` and is
defined as::

    static nghttp2_ssize send_callback(nghttp2_session *session _U_,
                                       const uint8_t *data, size_t length,
                                       int flags _U_, void *user_data) {
      http2_session_data *session_data = (http2_session_data *)user_data;
      struct bufferevent *bev = session_data->bev;
      bufferevent_write(bev, data, length);
      return (nghttp2_ssize)length;
    }

Since we use bufferevent to abstract network I/O, we just write the
data to the bufferevent object. Note that `nghttp2_session_send()`
continues to write all frames queued so far. If we were writing the
data to the non-blocking socket directly using the ``write()`` system
call, we'd soon receive an ``EAGAIN`` or ``EWOULDBLOCK`` error, since
sockets have a limited send buffer. If that happens, it's possible to
return :macro:`NGHTTP2_ERR_WOULDBLOCK` to signal the nghttp2 library
to stop sending further data. When writing to a bufferevent, you
should regulate the amount of data written, to avoid possible huge
memory consumption. In this example client however we don't implement
a limit. To see how to regulate the amount of buffered data, see the
``send_callback()`` in the server tutorial.

The third bufferevent callback is ``writecb()``, which is invoked when
all data written in the bufferevent output buffer has been sent::

    static void writecb(struct bufferevent *bev _U_, void *ptr) {
      http2_session_data *session_data = (http2_session_data *)ptr;
      if (nghttp2_session_want_read(session_data->session) == 0 &&
          nghttp2_session_want_write(session_data->session) == 0 &&
          evbuffer_get_length(bufferevent_get_output(session_data->bev)) == 0) {
        delete_http2_session_data(session_data);
      }
    }

As described earlier, we just write off all data in `send_callback()`,
so there is no data to write in this function. All we have to do is
check if the connection should be dropped or not. The nghttp2 session
object keeps track of reception and transmission of GOAWAY frames and
other error conditions. Using this information, the nghttp2 session
object can state whether the connection should be dropped or not.
More specifically, when both `nghttp2_session_want_read()` and
`nghttp2_session_want_write()` return 0, the connection is no-longer
required and can be closed. Since we're using bufferevent and its
deferred callback option, the bufferevent output buffer may still
contain pending data when the ``writecb()`` is called. To handle this
situation, we also check whether the output buffer is empty or not. If
all of these conditions are met, then we drop the connection.

Now let's look at the remaining nghttp2 callbacks setup in the
``initialize_nghttp2_setup()`` function.

A server responds to the request by first sending a HEADERS frame.
The HEADERS frame consists of response header name/value pairs, and
the ``on_header_callback()`` is called for each name/value pair::

    static int on_header_callback(nghttp2_session *session _U_,
                                  const nghttp2_frame *frame, const uint8_t *name,
                                  size_t namelen, const uint8_t *value,
                                  size_t valuelen, uint8_t flags _U_,
                                  void *user_data) {
      http2_session_data *session_data = (http2_session_data *)user_data;
      switch (frame->hd.type) {
      case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            session_data->stream_data->stream_id == frame->hd.stream_id) {
          /* Print response headers for the initiated request. */
          print_header(stderr, name, namelen, value, valuelen);
          break;
        }
      }
      return 0;
    }

In this tutorial, we just print the name/value pairs on stderr.

After the HEADERS frame has been fully received (and thus all response
header name/value pairs have been received), the
``on_frame_recv_callback()`` function is called::

    static int on_frame_recv_callback(nghttp2_session *session _U_,
                                      const nghttp2_frame *frame, void *user_data) {
      http2_session_data *session_data = (http2_session_data *)user_data;
      switch (frame->hd.type) {
      case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
            session_data->stream_data->stream_id == frame->hd.stream_id) {
          fprintf(stderr, "All headers received\n");
        }
        break;
      }
      return 0;
    }

``on_frame_recv_callback()`` is called for other frame types too.

In this tutorial, we are just interested in the HTTP response HEADERS
frame. We check the frame type and its category (it should be
:macro:`NGHTTP2_HCAT_RESPONSE` for HTTP response HEADERS). We also
check its stream ID.

Next, zero or more DATA frames can be received. The
``on_data_chunk_recv_callback()`` function is invoked when a chunk of
data is received from the remote peer::

    static int on_data_chunk_recv_callback(nghttp2_session *session _U_,
                                           uint8_t flags _U_, int32_t stream_id,
                                           const uint8_t *data, size_t len,
                                           void *user_data) {
      http2_session_data *session_data = (http2_session_data *)user_data;
      if (session_data->stream_data->stream_id == stream_id) {
        fwrite(data, len, 1, stdout);
      }
      return 0;
    }

In our case, a chunk of data is HTTP response body. After checking the
stream ID, we just write the received data to stdout. Note the output
in the terminal may be corrupted if the response body contains some
binary data.

The ``on_stream_close_callback()`` function is invoked when the stream
is about to close::

    static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                        nghttp2_error_code error_code,
                                        void *user_data) {
      http2_session_data *session_data = (http2_session_data *)user_data;
      int rv;

      if (session_data->stream_data->stream_id == stream_id) {
        fprintf(stderr, "Stream %d closed with error_code=%d\n", stream_id,
                error_code);
        rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
        if (rv != 0) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
      return 0;
    }

If the stream ID matches the one we initiated, it means that its
stream is going to be closed. Since we have finished receiving
resource we wanted (or the stream was reset by RST_STREAM from the
remote peer), we call `nghttp2_session_terminate_session()` to
commence closure of the HTTP/2 session gracefully. If you have
some data associated for the stream to be closed, you may delete it
here.
