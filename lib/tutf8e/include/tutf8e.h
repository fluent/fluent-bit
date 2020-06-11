
#ifndef TUTF8E_H
#define TUTF8E_H

#include <stddef.h>  /* size_t */
#include <stdint.h>  /* uint16_t */
#include <string.h>

/* Generic API */

typedef void *TUTF8encoder;

extern int tutf8e_string_length(const TUTF8encoder encoder, const char *input, size_t *ilen, size_t *olen, uint32_t flags);
extern int tutf8e_string_encode(const TUTF8encoder encoder, const char *input, char *output, size_t *olen, uint32_t flags);
extern int tutf8e_buffer_length(const TUTF8encoder encoder, const char *input, size_t ilen, size_t *olen, uint32_t flags);
extern int tutf8e_buffer_encode(const TUTF8encoder encoder, const char *input, size_t ilen, char *output, size_t *olen, uint32_t flags);

extern TUTF8encoder tutf8e_encoder(const char *encoding);
extern uint32_t tutf8e_encoder_flag(const char *string_flag);

#define TUTF8E_OK       1 /* Sucesss : changed          */
#define TUTF8E_SAME     0 /* Success : no change        */
#define TUTF8E_INVALID -1 /* Invalid input character    */
#define TUTF8E_TOOLONG -2 /* Insufficient output buffer */



#define TUTF8E_FLAG_INV_KEEP         0    /* illegal char: keep, just use as unicode codepoint  */
#define TUTF8E_FLAG_INV_FAIL         1    /* illegal char: fail on invalid char */
#define TUTF8E_FLAG_INV_IGNORE       2    /* illegal char: skip/ignore invalid char */
#define TUTF8E_FLAG_INV_REPLACEMENT  3    /* illegal char: convert to replacement character  */
#define TUTF8E_FLAG_INV_QUESTION     4    /* illegal char: convert to '?' */
#define TUTF8E_FLAG_INV_COPY         5    /* illegal char: just copy byte */

#define TUTF8E_FLAG_INV_MASK      0x07    /* illegal char mask */

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
