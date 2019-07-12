/*
 * public domain sha512 crypt implementation
 *
 * This is based on the musl libc SHA512 implementation. Follow the
 * link for the original source code.
 * https://git.musl-libc.org/cgit/musl/tree/src/crypt/crypt_sha512.c?h=v1.1.22
 *
 * Here is how to use it:
 *
 * #include <fluent-bit/flb_sha512.h>
 *
 * void main(void)
 * {
 *     struct flb_sha512 sha512;
 *     char buf[64];
 *
 *     flb_sha512_init(&sha512);
 *     flb_sha512_update(&sha512, "aiueo", 5);
 *     flb_sha512_sum(&sha512, buf);
 * }
 */

#ifndef FLB_SHA512_H
#define FLB_SHA512_H

#include <stdint.h>

struct flb_sha512 {
	uint64_t len;     /* processed message length */
	uint64_t h[8];    /* hash state */
	uint8_t buf[128]; /* message block buffer */
};

void flb_sha512_init(struct flb_sha512 *s);
void flb_sha512_sum(struct flb_sha512 *s, uint8_t *md);
void flb_sha512_update(struct flb_sha512 *s, const void *m, unsigned long len);
#endif
