#include "cmac.h"
#include "aes.h"
#include "utils.h"

// Implementation in C from https://github.com/megrxu/AES-CMAC/blob/master/src/cmac.c
// Calculate the CAMC
unsigned char* aes_cmac(unsigned char* in, unsigned int length, unsigned char* out, unsigned char* key)
{

    unsigned char* K1;
    unsigned char* K2;
    K1 = (unsigned char*)malloc(32);
    K2 = (unsigned char*)malloc(32);
    GenerateSubkey(key, K1, K2);

    int n = (length / const_Bsize);
    bool flag = false;
    if (length % const_Bsize != 0) {
        n++;
    }

    if (n == 0) {
        n = 1;
    } else if (length % const_Bsize == 0) {
        flag = true;
    }

    unsigned char M[n][const_Bsize];
    memset(M[0], 0, n * const_Bsize);
    memcpy(M[0], in, length);
    if (!flag) {
        memset(M[0] + length, 0x80, 1);
    }
    if (flag) {
        block_xor(M[n - 1], M[n - 1], K1);
    } else {
        block_xor(M[n - 1], M[n - 1], K2);
    }

    unsigned char X[] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    unsigned char Y[const_Bsize];

    for (auto i = 0; i < n - 1; i++) {
        block_xor(Y, M[i], X);
        aes_128_encrypt(Y, X, key);
    }
    block_xor(Y, M[n - 1], X);
    aes_128_encrypt(Y, out, key);
    free(K1);
    free(K2);
    return out;
}

// Verify the CMAC
bool verify_mac(unsigned char* in, unsigned int length, unsigned char* out, unsigned char* key)
{
    bool flag = true;
    unsigned char result[32];
    aes_cmac(in, length, (unsigned char*)result, key);
    for (auto i = 0; i < const_Bsize; i++) {
        if (!(result[i] ^ out[i])) {
            flag = false;
            break;
        }
    }
    return flag;
}

// Generate the Sub keys
void GenerateSubkey(unsigned char* key, unsigned char* K1, unsigned char* K2)
{
    unsigned char const_Zero[] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    unsigned char const_Rb[] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x87
    };

    unsigned char L[32];
    aes_128_encrypt(const_Zero, L, key);
    block_leftshift(K1, L);
    if (L[0] & 0x80) {
        block_xor(K1, K1, const_Rb);
    }

    block_leftshift(K2, K1);
    if (K1[0] & 0x80) {
        block_xor(K2, K2, const_Rb);
    }
}
