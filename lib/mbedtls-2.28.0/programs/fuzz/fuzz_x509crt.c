#include <stdint.h>
#include "mbedtls/x509_crt.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
#ifdef MBEDTLS_X509_CRT_PARSE_C
    int ret;
    mbedtls_x509_crt crt;
    unsigned char buf[4096];

    mbedtls_x509_crt_init( &crt );
    ret = mbedtls_x509_crt_parse( &crt, Data, Size );
    if (ret == 0) {
        ret = mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, " ", &crt );
    }
    mbedtls_x509_crt_free( &crt );
#else
    (void) Data;
    (void) Size;
#endif

    return 0;
}
