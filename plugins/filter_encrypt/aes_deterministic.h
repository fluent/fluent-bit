#include "cmac.h"
#include "crypto_utils.h"
#ifndef FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_LIBZ_AES_DETERMINISTIC_H_
#define FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_LIBZ_AES_DETERMINISTIC_H_

extern char KEY128[32];
extern char MASTER_KEY_SALT[32];

char * aes_det(const char* plaintext, const char* key, const char* salt);

#endif //FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_LIBZ_AES_DETERMINISTIC_H_
