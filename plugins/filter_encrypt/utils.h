#ifndef UTILS_H_
#define UTILS_H_

#include <stdio.h>
#include <string.h>

/* Function prototypes */
void print_bytes(unsigned char* buf, const size_t len);
void block_xor(unsigned char* dst, unsigned char* a, unsigned char* b);
void block_leftshift(unsigned char* dst, unsigned char* src);
char *concat(char *str1, const int str1_len, const char *str2, const int str2_len);
char* concaten(const unsigned char* str1, const int str1_len, const unsigned char* str2, const int str2_len);
char* substring(const char* input, size_t start, size_t length);
char* base64encode(const void* data, size_t input_length);
unsigned char* base64decode(const char* b64message, size_t b64message_len, size_t* output_length);
void populate_key_value_delimiters(char *value_delimiters);
void handleErrors(void);
#endif //UTILS_H_
