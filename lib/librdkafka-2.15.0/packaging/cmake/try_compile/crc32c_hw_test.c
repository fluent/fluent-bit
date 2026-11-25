#include <inttypes.h>
#include <stdio.h>
#define LONGx1 "8192"
#define LONGx2 "16384"
void main(void) {
        const char *n = "abcdefghijklmnopqrstuvwxyz0123456789";
        uint64_t c0 = 0, c1 = 1, c2 = 2;
        uint64_t s;
        uint32_t eax = 1, ecx;
        __asm__("cpuid" : "=c"(ecx) : "a"(eax) : "%ebx", "%edx");
        __asm__(
            "crc32b\t"
            "(%1), %0"
            : "=r"(c0)
            : "r"(n), "0"(c0));
        __asm__(
            "crc32q\t"
            "(%3), %0\n\t"
            "crc32q\t" LONGx1
            "(%3), %1\n\t"
            "crc32q\t" LONGx2 "(%3), %2"
            : "=r"(c0), "=r"(c1), "=r"(c2)
            : "r"(n), "0"(c0), "1"(c1), "2"(c2));
        s = c0 + c1 + c2;
        printf("avoiding unused code removal by printing %d, %d, %d\n", (int)s,
               (int)eax, (int)ecx);
}
