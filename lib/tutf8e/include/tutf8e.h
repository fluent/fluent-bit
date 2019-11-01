
#ifndef TUTF8E_H
#define TUTF8E_H

#include <stddef.h>  /* size_t */
#include <stdint.h>  /* uint16_t */

/* Internal API */

extern int tutf8e_string_length(const uint16_t *table, const char *i, size_t *ilen, size_t *olen);
extern int tutf8e_string_encode(const uint16_t *table, const char *i, char *o, size_t *olen);

extern int tutf8e_buffer_length(const uint16_t *table, const char *i, size_t ilen, size_t *olen);
extern int tutf8e_buffer_encode(const uint16_t *table, const char *i, size_t ilen, char *o, size_t *olen);

/* Generic API */

typedef void *TUTF8encoder;

extern TUTF8encoder tutf8e_encoder(const char *encoding);

#define TUTF8E_OK      0 /* Success                    */
#define TUTF8E_INVALID 1 /* Invalid input character    */
#define TUTF8E_TOOLONG 2 /* Insufficient output buffer */

static inline int tutf8e_encoder_string_length(const TUTF8encoder encoder, const char *i, size_t *ilen, size_t *olen)
{
  return tutf8e_string_length((const uint16_t *) encoder, i, ilen, olen);
}

static inline int tutf8e_encoder_string_encode(const TUTF8encoder encoder, const char *i, char *o, size_t *olen)
{
  return tutf8e_string_encode((const uint16_t *) encoder, i, o, olen);
}

static inline int tutf8e_encoder_buffer_length(const TUTF8encoder encoder, const char *i, size_t ilen, size_t *length)
{
  return tutf8e_buffer_length((const uint16_t *) encoder, i, ilen, length);
}

static inline int tutf8e_encoder_buffer_encode(const TUTF8encoder encoder, const char *i, size_t ilen, char *o, size_t *olen)
{
  return tutf8e_buffer_encode((const uint16_t *) encoder, i, ilen, o, olen);
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
