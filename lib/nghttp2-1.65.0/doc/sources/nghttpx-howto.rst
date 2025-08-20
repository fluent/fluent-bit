.. program:: nghttpx

nghttpx - HTTP/2 proxy - HOW-TO
===============================

:doc:`nghttpx.1` is a proxy translating protocols between HTTP/2 and
other protocols (e.g., HTTP/1).  It operates in several modes and each
mode may require additional programs to work with.  This article
describes each operation mode and explains the intended use-cases.  It
also covers some useful options later.

Default mode
------------

If nghttpx is invoked without :option:`--http2-proxy`, it operates in
default mode.  In this mode, it works as reverse proxy (gateway) for
HTTP/3, HTTP/2 and HTTP/1 clients to backend servers.  This is also
known as "HTTP/2 router".

By default, frontend connection is encrypted using SSL/TLS.  So
server's private key and certificate must be supplied to the command
line (or through configuration file).  In this case, the frontend
protocol selection will be done via ALPN.

To turn off encryption on frontend connection, use ``no-tls`` keyword
in :option:`--frontend` option.  HTTP/2 and HTTP/1 are available on
the frontend, and an HTTP/1 connection can be upgraded to HTTP/2 using
HTTP Upgrade.  Starting HTTP/2 connection by sending HTTP/2 connection
preface is also supported.

In order to receive HTTP/3 traffic, use ``quic`` parameter in
:option:`--frontend` option (.e.g, ``--frontend='*,443;quic'``)

nghttpx can listen on multiple frontend addresses.  This is achieved
by using multiple :option:`--frontend` options.  For each frontend
address, TLS can be enabled or disabled.

By default, backend connections are not encrypted.  To enable TLS
encryption on backend connections, use ``tls`` keyword in
:option:`--backend` option.  Using patterns and ``proto`` keyword in
:option:`--backend` option, backend application protocol can be
specified per host/request path pattern.  It means that you can use
both HTTP/2 and HTTP/1 in backend connections at the same time.  Note
that default backend protocol is HTTP/1.1.  To use HTTP/2 in backend,
you have to specify ``h2`` in ``proto`` keyword in :option:`--backend`
explicitly.

The backend is supposed to be a Web server.  For example, to make
nghttpx listen to encrypted HTTP/2 requests at port 8443, and a
backend Web server is configured to listen to HTTP requests at port
8080 on the same host, run nghttpx command-line like this:

.. code-block:: text

    $ nghttpx -f0.0.0.0,8443 -b127.0.0.1,8080 /path/to/server.key /path/to/server.crt

Then an HTTP/2 enabled client can access the nghttpx server using HTTP/2.  For
example, you can send a GET request using nghttp:

.. code-block:: text

    $ nghttp -nv https://localhost:8443/

HTTP/2 proxy mode
-----------------

If nghttpx is invoked with :option:`--http2-proxy` (or its shorthand
:option:`-s`) option, it operates in HTTP/2 proxy mode.  The supported
protocols in frontend and backend connections are the same as in `default
mode`_.  The difference is that this mode acts like a forward proxy and
assumes the backend is an HTTP proxy server (e.g., Squid, Apache Traffic
Server).  HTTP/1 requests must include an absolute URI in request line.

By default, the frontend connection is encrypted.  So this mode is
also called secure proxy.

To turn off encryption on the frontend connection, use ``no-tls`` keyword
in :option:`--frontend` option.

The backend must be an HTTP proxy server.  nghttpx supports multiple
backend server addresses.  It translates incoming requests to HTTP
request to backend server.  The backend server performs real proxy
work for each request, for example, dispatching requests to the origin
server and caching contents.

The backend connection is not encrypted by default.  To enable
encryption, use ``tls`` keyword in :option:`--backend` option.  The
default backend protocol is HTTP/1.1.  To use HTTP/2 in backend
connection, use :option:`--backend` option, and specify ``h2`` in
``proto`` keyword explicitly.

For example, to make nghttpx listen to encrypted HTTP/2 requests at
port 8443, and a backend HTTP proxy server is configured to listen to
HTTP/1 requests at port 8080 on the same host, run nghttpx command-line
like this:

.. code-block:: text

    $ nghttpx -s -f'*,8443' -b127.0.0.1,8080 /path/to/server.key /path/to/server.crt

At the time of this writing, Firefox 41 and Chromium v46 can use
nghttpx as HTTP/2 proxy.

To make Firefox or Chromium use nghttpx as HTTP/2 proxy, user has to
create proxy.pac script file like this:

.. code-block:: javascript

    function FindProxyForURL(url, host) {
        return "HTTPS SERVERADDR:PORT";
    }

``SERVERADDR`` and ``PORT`` is the hostname/address and port of the
machine nghttpx is running.  Please note that both Firefox and
Chromium require valid certificate for secure proxy.

For Firefox, open Preference window and select Advanced then click
Network tab.  Clicking Connection Settings button will show the
dialog.  Select "Automatic proxy configuration URL" and enter the path
to proxy.pac file, something like this:

.. code-block:: text

    file:///path/to/proxy.pac

For Chromium, use following command-line:

.. code-block:: text

    $ google-chrome --proxy-pac-url=file:///path/to/proxy.pac --use-npn

As HTTP/1 proxy server, Squid may work as out-of-box.  Traffic server
requires to be configured as forward proxy.  Here is the minimum
configuration items to edit:

.. code-block:: text

    CONFIG proxy.config.reverse_proxy.enabled INT 0
    CONFIG proxy.config.url_remap.remap_required INT 0

Consult Traffic server `documentation
<http://trafficserver.readthedocs.org/en/latest/admin-guide/configuration/transparent-forward-proxying.en.html>`_
to know how to configure traffic server as forward proxy and its
security implications.

ALPN support
------------

ALPN support requires OpenSSL >= 1.0.2.

Disable frontend SSL/TLS
------------------------

The frontend connections are encrypted with SSL/TLS by default.  To
turn off SSL/TLS, use ``no-tls`` keyword in :option:`--frontend`
option.  If this option is used, the private key and certificate are
not required to run nghttpx.

Enable backend SSL/TLS
----------------------

The backend connections are not encrypted by default.  To enable
SSL/TLS encryption, use ``tls`` keyword in :option:`--backend` option.

Enable SSL/TLS on memcached connection
--------------------------------------

By default, memcached connection is not encrypted.  To enable
encryption, use ``tls`` keyword in
:option:`--tls-ticket-key-memcached` for TLS ticket key, and
:option:`--tls-session-cache-memcached` for TLS session cache.

Specifying additional server certificates
-----------------------------------------

nghttpx accepts additional server private key and certificate pairs
using :option:`--subcert` option.  It can be used multiple times.

Specifying additional CA certificate
------------------------------------

By default, nghttpx tries to read CA certificate from system.  But
depending on the system you use, this may fail or is not supported.
To specify CA certificate manually, use :option:`--cacert` option.
The specified file must be PEM format and can contain multiple
certificates.

By default, nghttpx validates server's certificate.  If you want to
turn off this validation, knowing this is really insecure and what you
are doing, you can use :option:`--insecure` option to disable
certificate validation.

Read/write rate limit
---------------------

nghttpx supports transfer rate limiting on frontend connections.  You
can do rate limit per frontend connection for reading and writing
individually.

To perform rate limit for reading, use :option:`--read-rate` and
:option:`--read-burst` options.  For writing, use
:option:`--write-rate` and :option:`--write-burst`.

Please note that rate limit is performed on top of TCP and nothing to
do with HTTP/2 flow control.

Rewriting location header field
-------------------------------

nghttpx automatically rewrites location response header field if the
following all conditions satisfy:

* In the default mode (:option:`--http2-proxy` is not used)
* :option:`--no-location-rewrite` is not used
* URI in location header field is an absolute URI
* URI in location header field includes non empty host component.
* host (without port) in URI in location header field must match the
  host appearing in ``:authority`` or ``host`` header field.

When rewrite happens, URI scheme is replaced with the ones used in
frontend, and authority is replaced with which appears in
``:authority``, or ``host`` request header field.  ``:authority``
header field has precedence over ``host``.

Hot swapping
------------

nghttpx supports hot swapping using signals.  The hot swapping in
nghttpx is multi step process.  First send USR2 signal to nghttpx
process.  It will do fork and execute new executable, using same
command-line arguments and environment variables.

As of nghttpx version 1.20.0, that is all you have to do.  The new
main process sends QUIT signal to the original process, when it is
ready to serve requests, to shut it down gracefully.

For earlier versions of nghttpx, you have to do one more thing.  At
this point, both current and new processes can accept requests.  To
gracefully shutdown current process, send QUIT signal to current
nghttpx process.  When all existing frontend connections are done, the
current process will exit.  At this point, only new nghttpx process
exists and serves incoming requests.

If you want to just reload configuration file without executing new
binary, send SIGHUP to nghttpx main process.

Re-opening log files
--------------------

When rotating log files, it is desirable to re-open log files after
log rotation daemon renamed existing log files.  To tell nghttpx to
re-open log files, send USR1 signal to nghttpx process.  It will
re-open files specified by :option:`--accesslog-file` and
:option:`--errorlog-file` options.

Multiple frontend addresses
---------------------------

nghttpx can listen on multiple frontend addresses.  To specify them,
just use :option:`--frontend` (or its shorthand :option:`-f`) option
repeatedly.  TLS can be enabled or disabled per frontend address
basis.  For example, to listen on port 443 with TLS enabled, and on
port 80 without TLS:

.. code-block:: text

   frontend=*,443
   frontend=*,80;no-tls


Multiple backend addresses
--------------------------

nghttpx supports multiple backend addresses.  To specify them, just
use :option:`--backend` (or its shorthand :option:`-b`) option
repeatedly.  For example, to use ``192.168.0.10:8080`` and
``192.168.0.11:8080``, use command-line like this:
``-b192.168.0.10,8080 -b192.168.0.11,8080``.  In configuration file,
this looks like:

.. code-block:: text

   backend=192.168.0.10,8080
   backend=192.168.0.11,8008

nghttpx can route request to different backend according to request
host and path.  For example, to route request destined to host
``doc.example.com`` to backend server ``docserv:3000``, you can write
like so:

.. code-block:: text

   backend=docserv,3000;doc.example.com/

When you write this option in command-line, you should enclose
argument with single or double quotes, since the character ``;`` has a
special meaning in shell.

To route, request to request path ``/foo`` to backend server
``[::1]:8080``, you can write like so:

.. code-block:: text

   backend=::1,8080;/foo

If the last character of path pattern is ``/``, all request paths
which start with that pattern match:

.. code-block:: text

   backend=::1,8080;/bar/

The request path ``/bar/buzz`` matches the ``/bar/``.

You can use ``*`` at the end of the path pattern to make it wildcard
pattern.  ``*`` must match at least one character:

.. code-block:: text

   backend=::1,8080;/sample*

The request path ``/sample1/foo`` matches the ``/sample*`` pattern.

Of course, you can specify both host and request path at the same
time:

.. code-block:: text

   backend=192.168.0.10,8080;example.com/foo

We can use ``*`` in the left most position of host to achieve wildcard
suffix match.  If ``*`` is the left most character, then the remaining
string should match the request host suffix.  ``*`` must match at
least one character.  For example, ``*.example.com`` matches
``www.example.com`` and ``dev.example.com``, and does not match
``example.com`` and ``nghttp2.org``.  The exact match (without ``*``)
always takes precedence over wildcard match.

One important thing you have to remember is that we have to specify
default routing pattern for so called "catch all" pattern.  To write
"catch all" pattern, just specify backend server address, without
pattern.

Usually, host is the value of ``Host`` header field.  In HTTP/2, the
value of ``:authority`` pseudo header field is used.

When you write multiple backend addresses sharing the same routing
pattern, they are used as load balancing.  For example, to use 2
servers ``serv1:3000`` and ``serv2:3000`` for request host
``example.com`` and path ``/myservice``, you can write like so:

.. code-block:: text

   backend=serv1,3000;example.com/myservice
   backend=serv2,3000;example.com/myservice

You can also specify backend application protocol in
:option:`--backend` option using ``proto`` keyword after pattern.
Utilizing this allows ngttpx to route certain request to HTTP/2, other
requests to HTTP/1.  For example, to route requests to ``/ws/`` in
backend HTTP/1.1 connection, and use backend HTTP/2 for other
requests, do this:

.. code-block:: text

   backend=serv1,3000;/;proto=h2
   backend=serv1,3000;/ws/;proto=http/1.1

The default backend protocol is HTTP/1.1.

TLS can be enabled per pattern basis:

.. code-block:: text

   backend=serv1,8443;/;proto=h2;tls
   backend=serv2,8080;/ws/;proto=http/1.1

In the above case, connection to serv1 will be encrypted by TLS.  On
the other hand, connection to serv2 will not be encrypted by TLS.

Dynamic hostname lookup
-----------------------

By default, nghttpx performs backend hostname lookup at start up, or
configuration reload, and keeps using them in its entire session.  To
make nghttpx perform hostname lookup dynamically, use ``dns``
parameter in :option:`--backend` option, like so:

.. code-block:: text

   backend=foo.example.com,80;;dns

nghttpx will cache resolved addresses for certain period of time.  To
change this cache period, use :option:`--dns-cache-timeout`.

Enable PROXY protocol
---------------------

PROXY protocol can be enabled per frontend.  In order to enable PROXY
protocol, use ``proxyproto`` parameter in :option:`--frontend` option,
like so:

.. code-block:: text

   frontend=*,443;proxyproto

nghttpx supports both PROXY protocol v1 and v2.  AF_UNIX in PROXY
protocol version 2 is ignored.

Session affinity
----------------

Two kinds of session affinity are available: client IP, and HTTP
Cookie.

To enable client IP based affinity, specify ``affinity=ip`` parameter
in :option:`--backend` option.  If PROXY protocol is enabled, then an
address obtained from PROXY protocol is taken into consideration.

To enable HTTP Cookie based affinity, specify ``affinity=cookie``
parameter, and specify a name of cookie in ``affinity-cookie-name``
parameter.  Optionally, a Path attribute can be specified in
``affinity-cookie-path`` parameter:

.. code-block:: text

   backend=127.0.0.1,3000;;affinity=cookie;affinity-cookie-name=nghttpxlb;affinity-cookie-path=/

Secure attribute of cookie is set if client connection is protected by
TLS.  ``affinity-cookie-stickiness`` specifies the stickiness of this
affinity.  If ``loose`` is given, which is the default, removing or
adding a backend server might break affinity.  While ``strict`` is
given, removing the designated backend server breaks affinity, but
adding new backend server does not cause breakage.

PSK cipher suites
-----------------

nghttpx supports pre-shared key (PSK) cipher suites for both frontend
and backend TLS connections.  For frontend connection, use
:option:`--psk-secrets` option to specify a file which contains PSK
identity and secrets.  The format of the file is
``<identity>:<hex-secret>``, where ``<identity>`` is PSK identity, and
``<hex-secret>`` is PSK secret in hex, like so:

.. code-block:: text

   client1:9567800e065e078085c241d54a01c6c3f24b3bab71a606600f4c6ad2c134f3b9
   client2:b1376c3f8f6dcf7c886c5bdcceecd1e6f1d708622b6ddd21bda26ebd0c0bca99

nghttpx server accepts any of the identity and secret pairs in the
file.  The default cipher suite list does not contain PSK cipher
suites.  In order to use PSK, PSK cipher suite must be enabled by
using :option:`--ciphers` option.  The desired PSK cipher suite may be
listed in `HTTP/2 cipher block list
<https://tools.ietf.org/html/rfc7540#appendix-A>`_.  In order to use
such PSK cipher suite with HTTP/2, disable HTTP/2 cipher block list by
using :option:`--no-http2-cipher-block-list` option.  But you should
understand its implications.

At the time of writing, even if only PSK cipher suites are specified
in :option:`--ciphers` option, certificate and private key are still
required.

For backend connection, use :option:`--client-psk-secrets` option to
specify a file which contains single PSK identity and secret.  The
format is the same as the file used by :option:`--psk-secrets`
described above, but only first identity and secret pair is solely
used, like so:

.. code-block:: text

   client2:b1376c3f8f6dcf7c886c5bdcceecd1e6f1d708622b6ddd21bda26ebd0c0bca99

The default cipher suite list does not contain PSK cipher suites.  In
order to use PSK, PSK cipher suite must be enabled by using
:option:`--client-ciphers` option.  The desired PSK cipher suite may
be listed in `HTTP/2 cipher block list
<https://tools.ietf.org/html/rfc7540#appendix-A>`_.  In order to use
such PSK cipher suite with HTTP/2, disable HTTP/2 cipher block list by
using :option:`--client-no-http2-cipher-block-list` option.  But you
should understand its implications.

TLSv1.3
-------

As of nghttpx v1.34.0, if it is built with OpenSSL 1.1.1 or later, it
supports TLSv1.3.  0-RTT data is supported, but by default its
processing is postponed until TLS handshake completes to mitigate
replay attack.  This costs extra round trip and reduces effectiveness
of 0-RTT data.  :option:`--tls-no-postpone-early-data` makes nghttpx
not wait for handshake to complete before forwarding request included
in 0-RTT to get full potential of 0-RTT data.  In this case, nghttpx
adds ``Early-Data: 1`` header field when forwarding a request to a
backend server.  All backend servers should recognize this header
field and understand that there is a risk for replay attack.  See `RFC
8470 <https://tools.ietf.org/html/rfc8470>`_ for ``Early-Data`` header
field.

nghttpx disables anti replay protection provided by OpenSSL.  The anti
replay protection of OpenSSL requires that a resumed request must hit
the same server which generates the session ticket.  Therefore it
might not work nicely in a deployment where there are multiple nghttpx
instances sharing ticket encryption keys via memcached.

Because TLSv1.3 completely changes the semantics of cipher suite
naming scheme and structure, nghttpx provides the new option
:option:`--tls13-ciphers` and :option:`--tls13-client-ciphers` to
change preferred cipher list for TLSv1.3.

WebSockets over HTTP/2
----------------------

nghttpx supports `RFC 8441 <https://tools.ietf.org/html/rfc8441>`_
Bootstrapping WebSockets with HTTP/2 for both frontend and backend
connections.  This feature is enabled by default and no configuration
is required.

WebSockets over HTTP/3 is also supported.

HTTP/3
------

nghttpx supports HTTP/3 if it is built with HTTP/3 support enabled.
HTTP/3 support is experimental.

In order to listen UDP port to receive HTTP/3 traffic,
:option:`--frontend` option must have ``quic`` parameter:

.. code-block:: text

   frontend=*,443;quic

The above example makes nghttpx receive HTTP/3 traffic on UDP
port 443.

nghttpx does not support HTTP/3 on backend connection.

Hot swapping (SIGUSR2) or configuration reload (SIGHUP) require eBPF
program.  Without eBPF, old worker processes keep getting HTTP/3
traffic and do not work as intended.  The QUIC keying material to
encrypt Connection ID must be set with
:option:`--frontend-quic-secret-file` and must provide the existing
keys in order to keep the existing connections alive during reload.

The construction of Connection ID closely follows Block Cipher CID
Algorithm described in `QUIC-LB draft
<https://datatracker.ietf.org/doc/html/draft-ietf-quic-load-balancers>`_.
A Connection ID that nghttpx generates is always 17 bytes long.  It
uses first 3 bits as a configuration ID.  The remaining bits in the
first byte are reserved and random.  The next 4 bytes are server ID.
The next 4 bytes are used to route UDP datagram to a correct
``SO_REUSEPORT`` socket.  The remaining bytes are randomly generated.
The server ID and the next 12 bytes are encrypted with AES-ECB.  The
key is derived from the keying materials stored in a file specified by
:option:`--frontend-quic-secret-file`.  The first 2 bits of keying
material in the file is used as a configuration ID.  The remaining
bits and following 3 bytes are reserved and unused.  The next 32 bytes
are used as an initial secret.  The remaining 32 bytes are used as a
salt.  The encryption key is generated by `HKDF
<https://datatracker.ietf.org/doc/html/rfc5869>`_ with SHA256 and
these keying materials and ``connection id encryption key`` as info.

In order announce that HTTP/3 endpoint is available, you should
specify alt-svc header field.  For example, the following options send
alt-svc header field in HTTP/1.1 and HTTP/2 response:

.. code-block:: text

   altsvc=h3,443,,,ma=3600
   http2-altsvc=h3,443,,,ma=3600

Migration from nghttpx v1.18.x or earlier
-----------------------------------------

As of nghttpx v1.19.0, :option:`--ciphers` option only changes cipher
list for frontend TLS connection.  In order to change cipher list for
backend connection, use :option:`--client-ciphers` option.

Similarly, :option:`--no-http2-cipher-block-list` option only disables
HTTP/2 cipher block list for frontend connection.  In order to disable
HTTP/2 cipher block list for backend connection, use
:option:`--client-no-http2-cipher-block-list` option.

``--accept-proxy-protocol`` option was deprecated.  Instead, use
``proxyproto`` parameter in :option:`--frontend` option to enable
PROXY protocol support per frontend.

Migration from nghttpx v1.8.0 or earlier
----------------------------------------

As of nghttpx 1.9.0, ``--frontend-no-tls`` and ``--backend-no-tls``
have been removed.

To disable encryption on frontend connection, use ``no-tls`` keyword
in :option:`--frontend` potion:

.. code-block:: text

   frontend=*,3000;no-tls

The TLS encryption is now disabled on backend connection in all modes
by default.  To enable encryption on backend connection, use ``tls``
keyword in :option:`--backend` option:

.. code-block:: text

   backend=127.0.0.1,8080;tls

As of nghttpx 1.9.0, ``--http2-bridge``, ``--client`` and
``--client-proxy`` options have been removed.  These functionality can
be used using combinations of options.

Use following option instead of ``--http2-bridge``:

.. code-block:: text

   backend=<ADDR>,<PORT>;;proto=h2;tls

Use following options instead of ``--client``:

.. code-block:: text

   frontend=<ADDR>,<PORT>;no-tls
   backend=<ADDR>,<PORT>;;proto=h2;tls

Use following options instead of ``--client-proxy``:

.. code-block:: text

   http2-proxy=yes
   frontend=<ADDR>,<PORT>;no-tls
   backend=<ADDR>,<PORT>;;proto=h2;tls

We also removed ``--backend-http2-connections-per-worker`` option.  It
was present because previously the number of backend h2 connection was
statically configured, and defaulted to 1.  Now the number of backend
h2 connection is increased on demand.  We know the maximum number of
concurrent streams per connection.  When we push as many request as
the maximum concurrency to the one connection, we create another new
connection so that we can distribute load and avoid delay the request
processing.  This is done automatically without any configuration.
