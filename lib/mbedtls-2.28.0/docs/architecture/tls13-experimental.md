TLS 1.3 Experimental Developments
=================================

Overview
--------

Mbed TLS doesn't support the TLS 1.3 protocol yet, but a prototype is in development.
Stable parts of this prototype that can be independently tested are being successively
upstreamed under the guard of the following macro:

```
MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
```

This macro will likely be renamed to `MBEDTLS_SSL_PROTO_TLS1_3` once a minimal viable
implementation of the TLS 1.3 protocol is available.

See the [documentation of `MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL`](../../include/mbedtls/config.h)
for more information.

Status
------

The following lists which parts of the TLS 1.3 prototype have already been upstreamed
together with their level of testing:

* TLS 1.3 record protection mechanisms

  The record protection routines `mbedtls_ssl_{encrypt|decrypt}_buf()` have been extended
  to support the modified TLS 1.3 record protection mechanism, including modified computation
  of AAD, IV, and the introduction of a flexible padding.

  Those record protection routines have unit tests in `test_suite_ssl` alongside the
  tests for the other record protection routines.

  TODO: Add some test vectors from RFC 8448.

- The HKDF key derivation function on which the TLS 1.3 key schedule is based,
  is already present as an independent module controlled by `MBEDTLS_HKDF_C`
  independently of the development of the TLS 1.3 prototype.

- The TLS 1.3-specific HKDF-based key derivation functions (see RFC 8446):
  * HKDF-Expand-Label
  * Derive-Secret
  - Secret evolution
  * The traffic {Key,IV} generation from secret
  Those functions are implemented in `library/ssl_tls13_keys.c` and
  tested in `test_suite_ssl` using test vectors from RFC 8448 and
  https://tls13.ulfheim.net/.

- New TLS Message Processing Stack (MPS)

  The TLS 1.3 prototype is developed alongside a rewrite of the TLS messaging layer,
  encompassing low-level details such as record parsing, handshake reassembly, and
  DTLS retransmission state machine.

  MPS has the following components:
  - Layer 1 (Datagram handling)
  - Layer 2 (Record handling)
  - Layer 3 (Message handling)
  - Layer 4 (Retransmission State Machine)
  - Reader  (Abstracted pointer arithmetic and reassembly logic for incoming data)
  - Writer  (Abstracted pointer arithmetic and fragmentation logic for outgoing data)

  Of those components, the following have been upstreamed
  as part of `MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL`:

  - Reader ([`library/mps_reader.h`](../../library/mps_reader.h))
