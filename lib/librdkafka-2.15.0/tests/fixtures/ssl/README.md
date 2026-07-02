# SSL keys generation for tests

The Makefile in this directory generates a PKCS#12 keystore 
and corresponding PEM certificate and key for testing 
SSL keys and keystore usage in librdkafka.

To update those files with a newer OpenSSL version, just run `make`.

# Requirements

* OpenSSL >= 1.1.1
* Java keytool >= Java 11
* GNU Make >= 4.2