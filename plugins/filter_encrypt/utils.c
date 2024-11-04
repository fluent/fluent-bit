/* Base64 decode data with output length */
/* utils.c */

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <ctype.h>
#include "utils.h"

/* Function to print bytes in hexadecimal format */
void print_bytes(unsigned char* buf, const size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

/* Function to perform XOR operation on two blocks */
void block_xor(unsigned char* dst, unsigned char* a, unsigned char* b)
{
    for (int j = 0; j < 16; j++) {
        dst[j] = a[j] ^ b[j];
    }
}

/* Function to perform left shift on a block */
void block_leftshift(unsigned char* dst, unsigned char* src)
{
    unsigned char ovf = 0x00;
    for (int i = 15; i >= 0; i--) {
        dst[i] = src[i] << 1;
        dst[i] |= ovf;
        ovf = (src[i] & 0x80) ? 1 : 0;
    }
}

/* Function to concatenate two strings into a new buffer */
char* concaten(const char* str1, const int str1_len, const char* str2, const int str2_len)
{
    char* result = malloc(str1_len + str2_len + 1);
    if (!result) {
        perror("malloc");
        return NULL;
    }
    memcpy(result, str1, str1_len);
    memcpy(result + str1_len, str2, str2_len);
    result[str1_len + str2_len] = '\0';
    return result;
}

/* Function to extract a substring from a string */
char* substring(const char* input, size_t start, size_t length) {
    if (input == NULL) {
        return NULL;
    }

    size_t input_len = strlen(input);
    if (start >= input_len) {
        /* Start index is beyond the input string length */
        return NULL;
    }

    if (start + length > input_len) {
        /* Adjust length if it goes beyond the input string */
        length = input_len - start;
    }

    char* substring_buffer = malloc(length + 1);
    if (!substring_buffer) {
        perror("malloc");
        return NULL;
    }

    memcpy(substring_buffer, input + start, length);
    substring_buffer[length] = '\0';
    return substring_buffer;
}

char* base64encode(const void* data, size_t input_length) {
    BIO* b64 = NULL;
    BIO* mem = NULL;
    BUF_MEM* buffer_ptr = NULL;
    char* b64text = NULL;

    /* Create a Base64 filter BIO */
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        perror("BIO_new (b64)");
        return NULL;
    }

    /* Create a memory BIO */
    mem = BIO_new(BIO_s_mem());
    if (!mem) {
        perror("BIO_new (mem)");
        BIO_free_all(b64);
        return NULL;
    }

    /* Chain the BIOs: b64 -> mem */
    b64 = BIO_push(b64, mem);

    /* Do not use newlines to flush buffer */
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    /* Write the data to BIO */
    if (BIO_write(b64, data, input_length) <= 0) {
        perror("BIO_write");
        BIO_free_all(b64);
        return NULL;
    }

    /* Flush the BIO to ensure all data is written */
    if (BIO_flush(b64) != 1) {
        perror("BIO_flush");
        BIO_free_all(b64);
        return NULL;
    }

    /* Get the pointer to the memory BIO's buffer */
    BIO_get_mem_ptr(mem, &buffer_ptr);
    if (!buffer_ptr) {
        perror("BIO_get_mem_ptr");
        BIO_free_all(b64);
        return NULL;
    }

    /* Allocate memory for the encoded string (+1 for null terminator) */
    b64text = (char*)malloc(buffer_ptr->length + 1);
    if (!b64text) {
        perror("malloc");
        BIO_free_all(b64);
        return NULL;
    }

    /* Copy the Base64 encoded data into the allocated memory */
    memcpy(b64text, buffer_ptr->data, buffer_ptr->length);
    b64text[buffer_ptr->length] = '\0'; /* Null-terminate the string */

    /* Free the BIOs */
    BIO_free_all(b64);

    return b64text;
}


/* Base64 decode data with output length */
unsigned char* base64decode(const char* b64message, size_t b64message_len, size_t* output_length) {
    BIO* b64 = NULL;
    BIO* mem = NULL;
    unsigned char* buffer = NULL;
    int decoded_length = 0;

    /* Create a Base64 filter BIO */
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        perror("BIO_new (b64)");
        return NULL;
    }

    /* Create a memory BIO with the input Base64 message */
    mem = BIO_new_mem_buf((void*)b64message, b64message_len);
    if (!mem) {
        perror("BIO_new_mem_buf");
        BIO_free_all(b64);
        return NULL;
    }

    /* Chain the BIOs: b64 -> mem */
    b64 = BIO_push(b64, mem);

    /* Do not use newlines to flush buffer */
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    /* Allocate memory for the decoded data */
    size_t max_decoded_size = b64message_len * 3 / 4 + 1;
    buffer = (unsigned char*)malloc(max_decoded_size);
    if (!buffer) {
        perror("malloc");
        BIO_free_all(b64);
        return NULL;
    }

    /* Read the decoded data from BIO */
    decoded_length = BIO_read(b64, buffer, max_decoded_size);
    if (decoded_length < 0) {
        perror("BIO_read");
        free(buffer);
        BIO_free_all(b64);
        return NULL;
    }

    /* Set the output length */
    *output_length = decoded_length;

    /* Optionally, null-terminate the decoded data if it's a string */
    /* Uncomment the following lines if needed */
    /*
    buffer = realloc(buffer, decoded_length + 1);
    if (!buffer) {
        perror("realloc");
        BIO_free_all(b64);
        return NULL;
    }
    buffer[decoded_length] = '\0';
    */

    /* Free the BIOs */
    BIO_free_all(b64);

    return buffer;
}

/* Populate delimiters for key-value string tokenization */
void populate_key_value_delimiters(char* value_delimiters) {
    int index = 0;
    int k = 1; /* Start from ASCII 1 */
    int end = 128; /* Up to ASCII 127 */

    for (; k < end; k++) {
        if (!isalnum(k)) {
            value_delimiters[index++] = (char)k;
        }
    }
    value_delimiters[index] = '\0';
}
