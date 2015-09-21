/**
 * @file
 * X.509 module documentation file.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/**
 * @addtogroup x509_module X.509 module
 *
 * The X.509 module provides X.509 support which includes:
 * - X.509 certificate (CRT) reading (see \c x509parse_crt() and
 *   \c x509parse_crtfile()).
 * - X.509 certificate revocation list (CRL) reading (see \c x509parse_crl()
 *   and\c x509parse_crlfile()).
 * - X.509 (RSA and ECC) private key reading (see \c x509parse_key() and
 *   \c x509parse_keyfile()).
 * - X.509 certificate signature verification (see \c x509parse_verify())
 * - X.509 certificate writing and certificate request writing (see
 *   \c mbedtls_x509write_crt_der() and \c mbedtls_x509write_csr_der()).
 *
 * This module can be used to build a certificate authority (CA) chain and
 * verify its signature. It is also used to generate Certificate Signing
 * Requests and X509 certificates just as a CA would do.
 */
