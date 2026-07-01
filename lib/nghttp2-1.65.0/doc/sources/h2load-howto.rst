.. program:: h2load

h2load - HTTP/2 benchmarking tool - HOW-TO
==========================================

:doc:`h2load.1` is benchmarking tool for HTTP/2 and HTTP/1.1.  It
supports SSL/TLS and clear text for all supported protocols.

Compiling from source
---------------------

h2load is compiled alongside nghttp2 and requires that the
``--enable-app`` flag is passed to ``./configure`` and `required
dependencies <https://github.com/nghttp2/nghttp2#requirements>`_ are
available during compilation. For details on compiling, see `nghttp2:
Building from Git
<https://github.com/nghttp2/nghttp2#building-from-git>`_.

Basic Usage
-----------

In order to set benchmark settings, specify following 3 options.

:option:`-n`
    The number of total requests.  Default: 1

:option:`-c`
    The number of concurrent clients.  Default: 1

:option:`-m`
   The max concurrent streams to issue per client.  Default: 1

For SSL/TLS connection, the protocol will be negotiated via ALPN.  You
can set specific protocols in :option:`--alpn-list` option.  For
cleartext connection, the default protocol is HTTP/2.  To change the
protocol in cleartext connection, use :option:`--no-tls-proto` option.
For convenience, :option:`--h1` option forces HTTP/1.1 for both
cleartext and SSL/TLS connections.

Here is a command-line to perform benchmark to URI \https://localhost
using total 100000 requests, 100 concurrent clients and 10 max
concurrent streams:

.. code-block:: text

    $ h2load -n100000 -c100 -m10 https://localhost

The benchmarking result looks like this:

.. code-block:: text

    finished in 7.08s, 141164.80 req/s, 555.33MB/s
    requests: 1000000 total, 1000000 started, 1000000 done, 1000000 succeeded, 0 failed, 0 errored, 0 timeout
    status codes: 1000000 2xx, 0 3xx, 0 4xx, 0 5xx
    traffic: 4125025824 bytes total, 11023424 bytes headers (space savings 93.07%), 4096000000 bytes data
                         min         max         mean         sd        +/- sd
    time for request:    15.31ms    146.85ms     69.78ms      9.26ms    92.43%
    time for connect:     1.08ms     25.04ms     10.71ms      9.80ms    64.00%
    time to 1st byte:    25.36ms    184.96ms     79.11ms     53.97ms    78.00%
    req/s (client)  :    1412.04     1447.84     1426.52       10.57    63.00%

See the h2load manual page :ref:`h2load-1-output` section for the
explanation of the above numbers.

Timing-based load-testing
-------------------------

As of v1.26.0, h2load supports timing-based load-testing.  This method
performs load-testing in terms of a given duration instead of a
pre-defined number of requests. The new option :option:`--duration`
specifies how long the load-testing takes. For example,
``--duration=10`` makes h2load perform load-testing against a server
for 10 seconds. You can also specify a “warming-up” period with
:option:`--warm-up-time`. If :option:`--duration` is used,
:option:`-n` option is ignored.

The following command performs load-testing for 10 seconds after 5
seconds warming up period:

.. code-block:: text

    $ h2load -c100 -m100 --duration=10 --warm-up-time=5 https://localhost

Flow Control
------------

HTTP/2 has flow control and it may affect benchmarking results.  By
default, h2load uses large enough flow control window, which
effectively disables flow control.  To adjust receiver flow control
window size, there are following options:

:option:`-w`
   Sets  the stream  level  initial  window size  to
   (2**<N>)-1.

:option:`-W`
   Sets the connection level  initial window size to
   (2**<N>)-1.

Multi-Threading
---------------

Sometimes benchmarking client itself becomes a bottleneck.  To remedy
this situation, use :option:`-t` option to specify the number of native
thread to use.

:option:`-t`
    The number of native threads. Default: 1

Selecting protocol for clear text
---------------------------------

By default, if \http:// URI is given, HTTP/2 protocol is used.  To
change the protocol to use for clear text, use :option:`-p` option.

Multiple URIs
-------------

If multiple URIs are specified, they are used in round robin manner.

.. note::

    Please note that h2load uses scheme, host and port in the first URI
    and ignores those parts in the rest of the URIs.

UNIX domain socket
------------------

To request against UNIX domain socket, use :option:`--base-uri`, and
specify ``unix:`` followed by the path to UNIX domain socket.  For
example, if UNIX domain socket is ``/tmp/nghttpx.sock``, use
``--base-uri=unix:/tmp/nghttpx.sock``.  h2load uses scheme, host and
port in the first URI in command-line or input file.

HTTP/3
------

h2load supports HTTP/3 if it is built with HTTP/3 enabled.  HTTP/3
support is experimental.

In order to send HTTP/3 request, specify ``h3`` to
:option:`--alpn-list`.
