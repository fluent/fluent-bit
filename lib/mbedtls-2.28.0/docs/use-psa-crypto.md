This document describes the compile-time configuration option
`MBEDTLS_USE_PSA_CRYPTO` from a user's perspective, more specifically its
current effects as well as the parts that aren't covered yet.

Current effects
===============

General limitations
-------------------

Compile-time: enabling `MBEDTLS_USE_PSA_CRYPTO` requires
`MBEDTLS_ECP_RESTARTABLE` and
`MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER` to be disabled.

Effect: `MBEDTLS_USE_PSA_CRYPTO` currently has no effect on TLS 1.3 (which is
itself experimental and only partially supported so far): TLS 1.3 always uses
the legacy APIs even when this option is set.

Stability: any API that's only available when `MBEDTLS_USE_PSA_CRYPTO` is
defined is considered experimental and may change in incompatible ways at any
time. Said otherwise, these APIs are explicitly excluded from the usual API
stability promises.

New APIs / API extensions
-------------------------

Some of these APIs are meant for the application to use in place of
pre-existing APIs, in order to get access to the benefits; in the sub-sections
below these are indicated by "Use in (X.509 and) TLS: opt-in", meaning that
this requires changes to the application code for the (X.509 and) TLS layers
to pick up the improvements.

Some of these APIs are mostly meant for internal use by the TLS (and X.509)
layers; they are indicated below by "Use in (X.509 and) TLS: automatic",
meaning that no changes to the application code are required for the TLS (and
X.509) layers to pick up the improvements.

### PSA-held (opaque) keys in the PK layer

There is a new API function `mbedtls_pk_setup_opaque()` that can be used to
wrap a PSA keypair into a PK context. The key can be used for private-key
operations and its public part can be exported.

Benefits: isolation of long-term secrets, use of PSA Crypto drivers.

Limitations: only for private keys, only ECC. (That is, only ECDSA signature
generation. Note: currently this will use randomized ECDSA while Mbed TLS uses
deterministic ECDSA by default.) The following operations are not supported
with a context set this way, while they would be available with a normal
`ECKEY` context: `mbedtls_pk_verify()`, `mbedtls_pk_check_pair()`,
`mbedtls_pk_debug()`.

Use in X.509 and TLS: opt-in. The application needs to construct the PK context
using the new API in order to get the benefits; it can then pass the
resulting context to the following existing APIs:

- `mbedtls_ssl_conf_own_cert()` or `mbedtls_ssl_set_hs_own_cert()` to use the
  key together with a certificate for ECDSA-based key exchanges (note: while
this is supported on both sides, it's currently only tested client-side);
- `mbedtls_x509write_csr_set_key()` to generate a CSR (certificate signature
  request).

In the TLS and X.509 API, there are two other functions which accept a key or
keypair as a PK context: `mbedtls_x509write_crt_set_subject_key()` and
`mbedtls_x509write_crt_set_issuer_key()`. Use of opaque contexts here probably
works but is so far untested.

### PSA-held (opaque) keys for TLS pre-shared keys (PSK)

There are two new API functions `mbedtls_ssl_conf_psk_opaque()` and
`mbedtls_ssl_set_hs_psk_opaque()`. Call one of these from an application to
register a PSA key for use with a PSK key exchange.

Benefits: isolation of long-term secrets.

Limitations: the key can only be used with "pure"
PSK key exchanges (ciphersuites starting with `TLS_PSK_WITH_`), to the
exclusion of RSA-PSK, DHE-PSK and ECDHE-PSK key exchanges. It is the responsibility of
the user to make sure that when provisioning an opaque pre-shared key, the
only PSK ciphersuites that can be negotiated are "pure" PSK; other XXX-PSK key
exchanges will result in a handshake failure with the handshake function
returning `MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE`.

Use in TLS: opt-in. The application needs to register the key using the new
APIs to get the benefits.

### PSA-based operations in the Cipher layer

There is a new API function `mbedtls_cipher_setup_psa()` to set up a context
that will call PSA to store the key and perform the operations.

Benefits: use of PSA Crypto drivers; partial isolation of short-term secrets
(still generated outside of PSA, but then held by PSA).

Limitations: the key is still passed in the clear by the application. The
multi-part APIs are not supported, only the one-shot APIs. The only modes
supported are ECB, CBC without padding, GCM and CCM (this excludes stream
ciphers and ChachaPoly); the only cipher supported is AES (this excludes Aria,
Camellia, and ChachaPoly). (Note: ECB is currently not tested.) (Note: it is
possible to perform multiple one-shot operations with the same context;
however this is not unit-tested, only tested via usage in TLS.)

Use in TLS: automatic. Used when the cipher and mode is supported (with
gracious fallback to the legacy API otherwise) in all places where a cipher is
used. There are two such places: in `ssl_tls.c` for record protection, and in
`ssl_ticket.c` for protecting tickets we issue.

Internal changes
----------------

All of these internal changes are active as soon as `MBEDTLS_USE_PSA_CRYPTO`
is enabled, no change required on the application side.

### TLS: cipher operations based on PSA

See "PSA-based operations in the Cipher layer" above.

### PK layer: ECDSA verification based on PSA

Scope: `mbedtls_pk_verify()` will call to PSA for ECDSA signature
verification.

Benefits: use of PSA Crypto drivers.

Use in TLS and X.509: in all places where an ECDSA signature is verified.

### TLS: ECDHE computation based on PSA

Scope: Client-side, for ECDHE-RSA and ECDHE-ECDSA key exchanges, the
computation of the ECDHE key exchange is done by PSA.

Limitations: client-side only, ECDHE-PSK not covered

Benefits: use of PSA Crypto drivers.

### TLS: handshake hashes and PRF computed with PSA

Scope: with TLS 1.2, the following are computed with PSA:
- the running handshake hashes;
- the hash of the ServerKeyExchange part that is signed;
- the `verify_data` part of the Finished message;
- the TLS PRF.

Benefits: use of PSA Crypto drivers.

### X.509: some hashes computed with PSA

Scope: the following hashes are computed with PSA:
- when verifying a certificate chain, hash of the child for verifying the
  parent's signature;
- when writing a CSR, hash of the request for self-signing the request.

Benefits: use of PSA Crypto drivers.

Parts that are not covered yet
==============================

This is only a high-level overview, grouped by theme

TLS: 1.3 experimental support
-----------------------------

No part of the experimental support for TLS 1.3 is covered at the moment.

TLS: key exchanges / asymmetric crypto
--------------------------------------

The following key exchanges are not covered at all:

- RSA
- DHE-RSA
- DHE-PSK
- RSA-PSK
- ECDHE-PSK
- ECDH-RSA
- ECDH-ECDSA
- ECJPAKE

The following key exchanges are only partially covered:

- ECDHE-RSA: RSA operations are not covered and, server-side, the ECDHE
  operation isn't either
- ECDHE-ECDSA: server-side, the ECDHE operation isn't covered. (ECDSA
  signature generation is only covered if using `mbedtls_pk_setup_opaque()`.)

PSK if covered when the application uses `mbedtls_ssl_conf_psk_opaque()` or
`mbedtls_ssl_set_hs_psk_opaque()`.

TLS: symmetric crypto
---------------------

- some ciphers not supported via PSA yet: ARIA, Camellia, ChachaPoly (silent
  fallback to the legacy APIs)
- the HMAC part of the CBC and NULL ciphersuites
- the HMAC computation in `ssl_cookie.c`

X.509
-----

- most hash operations are still done via the legacy API, except the few that
  are documented above as using PSA
- RSA PKCS#1 v1.5 signature generation (from PSA-held keys)
- RSA PKCS#1 v1.5 signature verification
- RSA-PSS signature verification
