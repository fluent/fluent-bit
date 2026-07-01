
#ifndef TUTF8E_H
#define TUTF8E_H

#include <stddef.h>  /* size_t */
#include <stdint.h>  /* uint16_t */

/*************** Internal API ***************/

/* NUL-terminated C-string API */

extern int tutf8e_string_length(const uint16_t *table, const char *input, const char *invalid, size_t *input_length, size_t *output_length);
extern int tutf8e_string_encode(const uint16_t *table, const char *input, const char *invalid, char *output, size_t *output_length);

/* Known-length buffer API */

extern int tutf8e_buffer_length(const uint16_t *table, const char *input, size_t input_length, const char *invalid, size_t *output_length);
extern int tutf8e_buffer_encode(const uint16_t *table, const char *input, size_t input_length, const char *invalid, char *output, size_t *output_length);

/*************** Public API ***************/

/* Opaque handle type */

typedef void *TUTF8encoder;

/* Query encoder by name */

extern TUTF8encoder tutf8e_encoder(const char *encoding);

#define TUTF8E_OK      0 /* Success                    */
#define TUTF8E_INVALID 1 /* Invalid input character    */
#define TUTF8E_TOOLONG 2 /* Insufficient output buffer */

/*
 * tutf8e_encoder_string_length
 *
 * Determine the length of input and UTF8 encoded output of NUL-terminated string
 * Performance: single pass O(n)
 *
 * output NUL terminator not counted
 *
 * - TUTF8E_INVALID if input character is not convertable
 * - TUTF8E_OK for success
 */

static inline int tutf8e_encoder_string_length(const TUTF8encoder encoder, const char *input, const char *invalid, size_t *input_length, size_t *output_length)
{
  return tutf8e_string_length((const uint16_t *) encoder, input, invalid, input_length, output_length);
}

/*
 * tutf8e_encoder_string_encode
 *
 * UTF8 encode NUL-terminated string
 * Performance: two pass O(n)
 *
 * output string is NUL terminated
 * output_length is output buffer size for input
 * output_length is encoded length for output, including NUL
 *
 * - TUTF8E_TOOLONG if output buffer insuficient
 * - TUTF8E_INVALID if input character is not convertable
 * - TUTF8E_OK for success
 */

static inline int tutf8e_encoder_string_encode(const TUTF8encoder encoder, const char *input, const char *invalid, char *output, size_t *output_length)
{
  return tutf8e_string_encode((const uint16_t *) encoder, input, invalid, output, output_length);
}

/* Known-length buffer API */

/*
 * tutf8e_encoder_buffer_length
 *
 * Determine the length of input and UTF8 encoded output of string
 * Performance: single pass O(n)
 *
 * output NUL terminator not counted
 *
 * - TUTF8E_INVALID if input character is not convertable
 * - TUTF8E_OK for success
 */

static inline int tutf8e_encoder_buffer_length(const TUTF8encoder encoder, const char *input, const char *invalid, size_t input_length, size_t *length)
{
  return tutf8e_buffer_length((const uint16_t *) encoder, input, input_length, invalid, length);
}

/*
 * tutf8e_encoder_buffer_encode
 *
 * UTF8 encode string
 * Performance: two pass O(n)
 *
 * output string is not NUL terminated
 *
 * output_length is output buffer size for input
 * output_length is encoded length for output
 *
 * - TUTF8E_TOOLONG if output buffer insuficient
 * - TUTF8E_INVALID if input character is not convertable
 * - TUTF8E_OK for success
 */

static inline int tutf8e_encoder_buffer_encode(const TUTF8encoder encoder, const char *input, size_t input_length, const char *invalid, char *output, size_t *output_length)
{
  return tutf8e_buffer_encode((const uint16_t *) encoder, input, input_length, invalid, output, output_length);
}

/* Supported encoders */

extern const TUTF8encoder tutf8e_encoder_iso_8859_1;
extern const TUTF8encoder tutf8e_encoder_iso_8859_10;
extern const TUTF8encoder tutf8e_encoder_iso_8859_11;
extern const TUTF8encoder tutf8e_encoder_iso_8859_13;
extern const TUTF8encoder tutf8e_encoder_iso_8859_14;
extern const TUTF8encoder tutf8e_encoder_iso_8859_15;
extern const TUTF8encoder tutf8e_encoder_iso_8859_16;
extern const TUTF8encoder tutf8e_encoder_iso_8859_2;
extern const TUTF8encoder tutf8e_encoder_iso_8859_3;
extern const TUTF8encoder tutf8e_encoder_iso_8859_4;
extern const TUTF8encoder tutf8e_encoder_iso_8859_5;
extern const TUTF8encoder tutf8e_encoder_iso_8859_6;
extern const TUTF8encoder tutf8e_encoder_iso_8859_7;
extern const TUTF8encoder tutf8e_encoder_iso_8859_8;
extern const TUTF8encoder tutf8e_encoder_iso_8859_9;
extern const TUTF8encoder tutf8e_encoder_windows_1250;
extern const TUTF8encoder tutf8e_encoder_windows_1251;
extern const TUTF8encoder tutf8e_encoder_windows_1252;
extern const TUTF8encoder tutf8e_encoder_windows_1253;
extern const TUTF8encoder tutf8e_encoder_windows_1254;
extern const TUTF8encoder tutf8e_encoder_windows_1255;
extern const TUTF8encoder tutf8e_encoder_windows_1256;
extern const TUTF8encoder tutf8e_encoder_windows_1257;
extern const TUTF8encoder tutf8e_encoder_windows_1258;

#endif
