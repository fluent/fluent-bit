/*
 *  Hello world example of a TLS client: fetch an HTTPS page
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

#if !defined(TARGET_LIKE_MBED)

#include <stdio.h>

int main() {
    printf("this program only works on mbed OS\n");
    return 0;
}

#else

/** \file main.cpp
 *  \brief An example TLS Client application
 *  This application sends an HTTPS request to developer.mbed.org and searches for a string in
 *  the result.
 *
 *  This example is implemented as a logic class (HelloHTTPS) wrapping a TCP socket.
 *  The logic class handles all events, leaving the main loop to just check if the process
 *  has finished.
 */

/* Change to a number between 1 and 4 to debug the TLS connection */
#define DEBUG_LEVEL 0

/* Change to 1 to skip certificate verification (UNSAFE, for debug only!) */
#define UNSAFE 0

#include "mbed.h"
#include "EthernetInterface.h"
#include "mbed-net-sockets/TCPStream.h"
#include "test_env.h"
#include "minar/minar.h"

#include "lwipv4_init.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

namespace {
const char *HTTPS_SERVER_NAME = "developer.mbed.org";
const int HTTPS_SERVER_PORT = 443;
const int RECV_BUFFER_SIZE = 600;

const char HTTPS_PATH[] = "/media/uploads/mbed_official/hello.txt";
const size_t HTTPS_PATH_LEN = sizeof(HTTPS_PATH) - 1;

/* Test related data */
const char *HTTPS_OK_STR = "200 OK";
const char *HTTPS_HELLO_STR = "Hello world!";

/* personalization string for the drbg */
const char *DRBG_PERS = "mbed TLS helloword client";

/* List of trusted root CA certificates
 * currently only GlobalSign, the CA for developer.mbed.org
 *
 * To add more than one root, just concatenate them.
 */
const char SSL_CA_PEM[] =
/* GlobalSign Root R1 SHA1/RSA/2048
 *   Serial no.  04 00 00 00 00 01 15 4b 5a c3 94 */
"-----BEGIN CERTIFICATE-----\n"
"MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\n"
"A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\n"
"b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\n"
"MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\n"
"YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\n"
"aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\n"
"jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\n"
"xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\n"
"1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\n"
"snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\n"
"U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\n"
"9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\n"
"BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\n"
"AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\n"
"yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\n"
"38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\n"
"AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\n"
"DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\n"
"HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\n"
"-----END CERTIFICATE-----\n";
}

using namespace mbed::Sockets::v0;

/**
 * \brief HelloHTTPS implements the logic for fetching a file from a webserver
 * using a TCP socket and parsing the result.
 */
class HelloHTTPS {
public:
    /**
     * HelloHTTPS Constructor
     * Initializes the TCP socket, sets up event handlers and flags.
     *
     * @param[in] domain The domain name to fetch from
     * @param[in] port The port of the HTTPS server
     */
    HelloHTTPS(const char * domain, const uint16_t port) :
            _stream(SOCKET_STACK_LWIP_IPV4), _domain(domain), _port(port)
    {

        _error = false;
        _gothello = false;
        _got200 = false;
        _bpos = 0;
        _request_sent = 0;
        _stream.open(SOCKET_AF_INET4);

        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
        mbedtls_x509_crt_init(&_cacert);
        mbedtls_ssl_init(&_ssl);
        mbedtls_ssl_config_init(&_ssl_conf);
    }
    /**
     * HelloHTTPS Desctructor
     */
    ~HelloHTTPS() {
        mbedtls_entropy_free(&_entropy);
        mbedtls_ctr_drbg_free(&_ctr_drbg);
        mbedtls_x509_crt_free(&_cacert);
        mbedtls_ssl_free(&_ssl);
        mbedtls_ssl_config_free(&_ssl_conf);
    }
    /**
     * Initiate the test.
     *
     * Starts by clearing test flags, then resolves the address with DNS.
     *
     * @param[in] path The path of the file to fetch from the HTTPS server
     * @return SOCKET_ERROR_NONE on success, or an error code on failure
     */
    void startTest(const char *path) {
        /* Initialize the flags */
        _got200 = false;
        _gothello = false;
        _error = false;
        _disconnected = false;
        _request_sent = false;
        /* Fill the request buffer */
        _bpos = snprintf(_buffer, sizeof(_buffer) - 1, "GET %s HTTP/1.1\nHost: %s\n\n", path, HTTPS_SERVER_NAME);

        /*
         * Initialize TLS-related stuf.
         */
        int ret;
        if ((ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                          (const unsigned char *) DRBG_PERS,
                          sizeof (DRBG_PERS))) != 0) {
            print_mbedtls_error("mbedtls_crt_drbg_init", ret);
            _error = true;
            return;
        }

        if ((ret = mbedtls_x509_crt_parse(&_cacert, (const unsigned char *) SSL_CA_PEM,
                           sizeof (SSL_CA_PEM))) != 0) {
            print_mbedtls_error("mbedtls_x509_crt_parse", ret);
            _error = true;
            return;
        }

        if ((ret = mbedtls_ssl_config_defaults(&_ssl_conf,
                        MBEDTLS_SSL_IS_CLIENT,
                        MBEDTLS_SSL_TRANSPORT_STREAM,
                        MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
            _error = true;
            return;
        }

        mbedtls_ssl_conf_ca_chain(&_ssl_conf, &_cacert, NULL);
        mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

#if UNSAFE
        mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
#endif

#if DEBUG_LEVEL > 0
        mbedtls_ssl_conf_verify(&_ssl_conf, my_verify, NULL);
        mbedtls_ssl_conf_dbg(&_ssl_conf, my_debug, NULL);
        mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

        if ((ret = mbedtls_ssl_setup(&_ssl, &_ssl_conf)) != 0) {
            print_mbedtls_error("mbedtls_ssl_setup", ret);
            _error = true;
            return;
        }

        mbedtls_ssl_set_hostname(&_ssl, HTTPS_SERVER_NAME);

        mbedtls_ssl_set_bio(&_ssl, static_cast<void *>(&_stream),
                                   ssl_send, ssl_recv, NULL );


        /* Connect to the server */
        printf("Starting DNS lookup for %s\r\n", _domain);
        /* Resolve the domain name: */
        socket_error_t err = _stream.resolve(_domain, TCPStream::DNSHandler_t(this, &HelloHTTPS::onDNS));
        _stream.error_check(err);
    }
    /**
     * Check if the test has completed.
     * @return Returns true if done, false otherwise.
     */
    bool done() {
        return _error || (_got200 && _gothello);
    }
    /**
     * Check if there was an error
     * @return Returns true if there was an error, false otherwise.
     */
    bool error() {
        return _error;
    }
    /**
     * Closes the TCP socket
     */
    void close() {
        _stream.close();
        while (!_disconnected)
            __WFI();
    }
protected:
    /**
     * Helper for pretty-printing mbed TLS error codes
     */
    static void print_mbedtls_error(const char *name, int err) {
        char buf[128];
        mbedtls_strerror(err, buf, sizeof (buf));
        printf("%s() failed: -0x%04x (%d): %s\r\n", name, -err, err, buf);
    }

#if DEBUG_LEVEL > 0
    /**
     * Debug callback for mbed TLS
     * Just prints on the USB serial port
     */
    static void my_debug(void *ctx, int level, const char *file, int line,
                         const char *str)
    {
        const char *p, *basename;
        (void) ctx;

        /* Extract basename from file */
        for(p = basename = file; *p != '\0'; p++) {
            if(*p == '/' || *p == '\\') {
                basename = p + 1;
            }
        }

        printf("%s:%04d: |%d| %s", basename, line, level, str);
    }

    /**
     * Certificate verification callback for mbed TLS
     * Here we only use it to display information on each cert in the chain
     */
    static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
    {
        char buf[1024];
        (void) data;

        printf("\nVerifying certificate at depth %d:\n", depth);
        mbedtls_x509_crt_info(buf, sizeof (buf) - 1, "  ", crt);
        printf("%s", buf);

        if (*flags == 0)
            printf("No verification issue for this certificate\n");
        else
        {
            mbedtls_x509_crt_verify_info(buf, sizeof (buf), "  ! ", *flags);
            printf("%s\n", buf);
        }

        return 0;
    }
#endif

    /**
     * Receive callback for mbed TLS
     */
    static int ssl_recv(void *ctx, unsigned char *buf, size_t len) {
        TCPStream *stream = static_cast<TCPStream *>(ctx);
        socket_error_t err = stream->recv(buf, &len);

        if (err == SOCKET_ERROR_NONE) {
            return static_cast<int>(len);
        } else if (err == SOCKET_ERROR_WOULD_BLOCK) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        } else {
            return -1;
        }
    }

    /**
     * Send callback for mbed TLS
     */
    static int ssl_send(void *ctx, const unsigned char *buf, size_t len) {
        TCPStream *stream = static_cast<TCPStream *>(ctx);

        socket_error_t err = stream->send(buf, len);

        if (err == SOCKET_ERROR_NONE) {
            return static_cast<int>(len);
        } else if (err == SOCKET_ERROR_WOULD_BLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        } else {
            return -1;
        }
    }

    void onError(Socket *s, socket_error_t err) {
        (void) s;
        printf("MBED: Socket Error: %s (%d)\r\n", socket_strerror(err), err);
        _stream.close();
        _error = true;
        MBED_HOSTTEST_RESULT(false);
    }
    /**
     * On Connect handler
     * Starts the TLS handshake
     */
    void onConnect(TCPStream *s) {
        char buf[16];
        _remoteAddr.fmtIPv4(buf,sizeof(buf));
        printf("Connected to %s:%d\r\n", buf, _port);

        s->setOnReadable(TCPStream::ReadableHandler_t(this, &HelloHTTPS::onReceive));
        s->setOnDisconnect(TCPStream::DisconnectHandler_t(this, &HelloHTTPS::onDisconnect));

        /* Start the handshake, the rest will be done in onReceive() */
        printf("Starting the TLS handshake...\r\n");
        int ret = mbedtls_ssl_handshake(&_ssl);
        if (ret < 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error("mbedtls_ssl_handshake", ret);
                onError(s, SOCKET_ERROR_UNKNOWN);
            }
            return;
        }
    }
    /**
     * On Receive handler
     * Parses the response from the server, to check for the HTTPS 200 status code and the expected response ("Hello World!")
     */
    void onReceive(Socket *s) {
        /* Send request if not done yet */
        if (!_request_sent) {
            int ret = mbedtls_ssl_write(&_ssl, (const unsigned char *) _buffer, _bpos);
            if (ret < 0) {
                if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                    ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    print_mbedtls_error("mbedtls_ssl_write", ret);
                    onError(s, SOCKET_ERROR_UNKNOWN);
                }
                return;
            }

            /* If we get here, the request was sent */
            _request_sent = 1;

            /* It also means the handshake is done, time to print info */
            printf("TLS connection to %s established\r\n", HTTPS_SERVER_NAME);
            {
                char buf[1024];
                mbedtls_x509_crt_info(buf, sizeof(buf), "\r    ",
                        mbedtls_ssl_get_peer_cert(&_ssl));
                printf("Server certificate:\r\n%s\r", buf);

#if defined(UNSAFE)
                uint32_t flags = mbedtls_ssl_get_verify_result(&_ssl);
                if( flags != 0 )
                {
                    mbedtls_x509_crt_verify_info(buf, sizeof (buf), "\r  ! ", flags);
                    printf("Certificate verification failed:\r\n%s\r\r\n", buf);
                }
                else
#endif
                    printf("Certificate verification passed\r\n\r\n");
            }
        }

        /* Read data out of the socket */
        int ret = mbedtls_ssl_read(&_ssl, (unsigned char *) _buffer, sizeof(_buffer));
        if (ret < 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error("mbedtls_ssl_read", ret);
                onError(s, SOCKET_ERROR_UNKNOWN);
            }
            return;
        }
        _bpos = static_cast<size_t>(ret);

        _buffer[_bpos] = 0;

        /* Check each of the flags */
        _got200 = _got200 || strstr(_buffer, HTTPS_OK_STR) != NULL;
        _gothello = _gothello || strstr(_buffer, HTTPS_HELLO_STR) != NULL;

        /* Print status messages */
        printf("HTTPS: Received %d chars from server\r\n", _bpos);
        printf("HTTPS: Received 200 OK status ... %s\r\n", _got200 ? "[OK]" : "[FAIL]");
        printf("HTTPS: Received '%s' status ... %s\r\n", HTTPS_HELLO_STR, _gothello ? "[OK]" : "[FAIL]");
        printf("HTTPS: Received message:\r\n\r\n");
        printf("%s", _buffer);
        _error = !(_got200 && _gothello);

        s->close();
    }
    /**
     * On DNS Handler
     * Reads the address returned by DNS, then starts the connect process.
     */
    void onDNS(Socket *s, struct socket_addr addr, const char *domain) {
        /* Check that the result is a valid DNS response */
        if (socket_addr_is_any(&addr)) {
            /* Could not find DNS entry */
            printf("Could not find DNS entry for %s", HTTPS_SERVER_NAME);
            onError(s, SOCKET_ERROR_DNS_FAILED);
        } else {
            /* Start connecting to the remote host */
            char buf[16];
            _remoteAddr.setAddr(&addr);
            _remoteAddr.fmtIPv4(buf,sizeof(buf));
            printf("DNS Response Received:\r\n%s: %s\r\n", domain, buf);
            printf("Connecting to %s:%d\r\n", buf, _port);
            socket_error_t err = _stream.connect(_remoteAddr, _port, TCPStream::ConnectHandler_t(this, &HelloHTTPS::onConnect));

            if (err != SOCKET_ERROR_NONE) {
                onError(s, err);
            }
        }
    }
    void onDisconnect(TCPStream *s) {
        s->close();
        MBED_HOSTTEST_RESULT(!error());
    }

protected:
    TCPStream _stream;              /**< The TCP Socket */
    const char *_domain;            /**< The domain name of the HTTPS server */
    const uint16_t _port;           /**< The HTTPS server port */
    char _buffer[RECV_BUFFER_SIZE]; /**< The response buffer */
    size_t _bpos;                   /**< The current offset in the response buffer */
    SocketAddr _remoteAddr;         /**< The remote address */
    volatile bool _got200;          /**< Status flag for HTTPS 200 */
    volatile bool _gothello;        /**< Status flag for finding the test string */
    volatile bool _error;           /**< Status flag for an error */
    volatile bool _disconnected;
    volatile bool _request_sent;

    mbedtls_entropy_context _entropy;
    mbedtls_ctr_drbg_context _ctr_drbg;
    mbedtls_x509_crt _cacert;
    mbedtls_ssl_context _ssl;
    mbedtls_ssl_config _ssl_conf;
};

/**
 * The main loop of the HTTPS Hello World test
 */
EthernetInterface eth;
HelloHTTPS *hello;

void app_start(int, char*[]) {
    /* The default 9600 bps is too slow to print full TLS debug info and could
     * cause the other party to time out. Select a higher baud rate for
     * printf(), regardless of debug level for the sake of uniformity. */
    Serial pc(USBTX, USBRX);
    pc.baud(115200);

    MBED_HOSTTEST_TIMEOUT(120);
    MBED_HOSTTEST_SELECT(default);
    MBED_HOSTTEST_DESCRIPTION(mbed TLS example HTTPS client);
    MBED_HOSTTEST_START("MBEDTLS_EX_HTTPS_CLIENT");

    /* Initialise with DHCP, connect, and start up the stack */
    eth.init();
    eth.connect();
    lwipv4_socket_init();

    hello = new HelloHTTPS(HTTPS_SERVER_NAME, HTTPS_SERVER_PORT);

    printf("Client IP Address is %s\r\n", eth.getIPAddress());

    mbed::util::FunctionPointer1<void, const char*> fp(hello, &HelloHTTPS::startTest);
    minar::Scheduler::postCallback(fp.bind(HTTPS_PATH));
}

#endif /* TARGET_LIKE_MBED */
