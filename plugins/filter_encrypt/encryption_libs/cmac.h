#ifndef CMAC_H
#define CMAC_H
#include <stdbool.h>
unsigned char* aes_cmac(unsigned char* in, unsigned int length, unsigned char* out, unsigned char* key);
#define const_Bsize 16

bool verify_mac(unsigned char* in, unsigned int length, unsigned char* out, unsigned char* key);

void GenerateSubkey(unsigned char* key, unsigned char* K1, unsigned char* K2);

#endif // !CMAC_H
