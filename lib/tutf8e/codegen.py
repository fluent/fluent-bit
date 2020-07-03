#!/usr/bin/env python3

encodings = [
  'windows-1250', 'windows-1251', 'windows-1252',
  'windows-1253', 'windows-1254', 'windows-1255',
  'windows-1256', 'windows-1257', 'windows-1258',
  'iso-8859-1', 'iso-8859-2',  'iso-8859-3',  'iso-8859-4',
  'iso-8859-5', 'iso-8859-6',  'iso-8859-7',  'iso-8859-8',
  'iso-8859-9', 'iso-8859-10', 'iso-8859-11', 'iso-8859-13',
  'iso-8859-14', 'iso-8859-15', 'iso-8859-16'
]

with open('include/tutf8e.h', 'w') as include:

  include.write('''
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

''')

  include.write('/* Supported encoders */\n\n')
  for e in sorted(encodings):
    name = e.replace('-', '_').lower()
    include.write('extern const TUTF8encoder tutf8e_encoder_%s;\n'%(name))

  include.write('\n')
  include.write('#endif\n')

with open('src/tutf8e.c', 'w') as src:

  src.write('''
#include <tutf8e.h>

#include <string.h>

int tutf8e_string_length(const uint16_t *table, const char *input, const char *invalid, size_t *input_length, size_t *output_length)
{
  const size_t invalid_length = invalid ? strlen(invalid) : 0;

  const unsigned char *i;
  for (i = (const unsigned char *) input; *i; ++i, (*input_length)++) {
    const uint16_t c = table[*i];
    if (c<0x80) {
      *output_length += 1;
      continue;
    }
    if (c<0x800) {
      *output_length += 2;
      continue;
    }
    if (c<0xffff) {
      *output_length += 3;
      continue;
    }
    if (invalid) {
      *output_length += invalid_length;
    }
    else {
      return TUTF8E_INVALID;
    }
  }
  return TUTF8E_OK;
}

int tutf8e_string_encode(const uint16_t *table, const char *input, const char *invalid, char *output, size_t *output_length)
{
  int ret;
  size_t input_length = 0;
  size_t encoded_length = 0;
  if (!(ret = tutf8e_string_length(table, input, invalid, &input_length, &encoded_length)))
  {
    if (encoded_length+1 > *output_length) return TUTF8E_TOOLONG;
    if (!(ret = tutf8e_buffer_encode(table, input, input_length, invalid, output, output_length)))
    {
      output[encoded_length] = 0;
      return TUTF8E_OK;
    }
  }
  return ret;
}

int tutf8e_buffer_length
(
  const uint16_t *table,
  const char *input,
  size_t input_length,
  const char *invalid,
  size_t *length
)
{
  const size_t invalid_length = invalid ? strlen(invalid) : 0;

  const unsigned char *i;
  for (i = (const unsigned char *) input; input_length; ++i, --input_length) {
    const uint16_t c = table[*i];
    if (c<0x80) {
      ++*length;
      continue;
    }
    if (c<0x800) {
      *length += 2;
      continue;
    }
    if (c<0xffff) {
      *length += 3;
      continue;
    }
    if (invalid) {
      *length += invalid_length;
    }
    else {
      return TUTF8E_INVALID;
    }
  }
  return TUTF8E_OK;
}

int tutf8e_buffer_encode
(
  const uint16_t *table,
  const char *input,
  size_t input_length,
  const char *invalid,
  char *output,
  size_t *output_length
)
{
  size_t invalid_length = invalid ? strlen(invalid) : 0;

  size_t left = *output_length;
  unsigned char *o = (unsigned char *) output;
  const unsigned char *i;
  for (i = (const unsigned char *) input; input_length; ++i, --input_length) {
    const uint16_t c = table[*i];
    if (c<0x80) {
      if (left<1) return TUTF8E_TOOLONG;
      *(o++) = c;
      left -= 1;
      continue;
    }
    if (c<0x800) {
      if (left<2) return TUTF8E_TOOLONG;
      *(o++) = 0xc0 | (c>>6);
      *(o++) = 0x80 | (c&0x3f);
      left -= 2;
      continue;
    }
    if (c<0xffff) {
      if (left<3) return TUTF8E_TOOLONG;
      *(o++) = 0xe0 | (c>>12);
      *(o++) = 0x80 | ((c>>6)&0x3f);
      *(o++) = 0x80 | (c&0x3f);
      left -= 3;
      continue;
    }
    if (invalid)
    {
      if (left<invalid_length) return TUTF8E_TOOLONG;
      if (invalid_length) {
        memcpy(o, invalid, invalid_length);
        o += invalid_length;
        left -= invalid_length;
      }
    }
    else {
      return TUTF8E_INVALID;
    }
  }
  *output_length -= left;
  return TUTF8E_OK;
}
''')

  for e in sorted(encodings):

    mapping  = {}
    domain   = []

    name = e.replace('-', '_').lower()

    v = []
    for i in range(0,256):
      try:
        v.append(ord(bytes([i]).decode(e)[0]))
      except:
        v.append(0xffff)
        pass

    src.write('\n')
    src.write('const uint16_t tutf8e_%s_utf8[256] =\n'%(name))
    src.write('{\n')
    for i in range(0,256,16):
      src.write('  %s,\n'%(', '.join([ '0x%04x'%(i) for i in v[i:i+16]])))
    src.write('};\n')

  src.write('\n')
  for e in sorted(encodings):
    name = e.replace('-', '_').lower()
    src.write('const TUTF8encoder tutf8e_encoder_%s = (TUTF8encoder) tutf8e_%s_utf8;\n'%(name, name))

  src.write('''
TUTF8encoder tutf8e_encoder(const char *encoding)
{
''')
  for e in sorted(encodings):
    name = e.replace('-', '_').lower()
    src.write('  if (!strcmp(encoding, "%s")) return tutf8e_encoder_%s;\n'%(e, name))
  src.write('''
  return NULL;
}
''')

for e in sorted(encodings):

  mapping  = {}
  domain   = []

  name = e.replace('-', '_').lower()
  with open('include/tutf8e/%s.h'%(name), 'w') as include:

    include.write('''
#ifndef TUTF8E_%s_H
#define TUTF8E_%s_H

#include <tutf8e.h>
'''%(name.upper(), name.upper()))

    include.write('''
static inline int tutf8e_%s_string_length(const char *input, const char *invalid, size_t *input_length, size_t *output_length)
{
  return tutf8e_encoder_string_length(tutf8e_encoder_%s, input, invalid, input_length, output_length);
}
'''%(name, name))

    include.write('''
static inline int tutf8e_%s_string_encode(const char *input, const char *invalid, char *output, size_t *output_length)
{
  return tutf8e_encoder_string_encode(tutf8e_encoder_%s, input, invalid, output, output_length);
}
'''%(name, name))

    include.write('''
static inline int tutf8e_%s_buffer_length(const char *i, size_t input_length, const char *invalid, size_t *length)
{
  return tutf8e_encoder_buffer_length(tutf8e_encoder_%s, input, input_length, invalid, length);
}
'''%(name, name))

    include.write('''
static inline int tutf8e_%s_buffer_encode(const char *i, size_t input_length, const char *invalid, char *output, size_t *output_length)
{
  return tutf8e_encoder_buffer_encode(tutf8e_encoder_%s, input, input_length, invalid, output, output_length);
}
'''%(name, name))

    include.write('\n')
    include.write('#endif\n')

# TESTS

# List of pangrams
# http://clagnut.com/blog/2380/

tests = [
  ('english',  'iso-8859-1',  'A quick brown fox jumps over the lazy dog'),
  ('finnish',  'iso-8859-1',  'Albert osti fagotin ja töräytti puhkuvan melodian.'),
  ('czech',    'iso-8859-2',  'Nechť již hříšné saxofony ďáblů rozezvučí síň úděsnými tóny waltzu, tanga a quickstepu.'),
  ('turkish',  'iso-8859-3',  'Pijamalı hasta yağız şoföre çabucak güvendi.'),
  ('estonian', 'iso-8859-4',  'Põdur Zagrebi tšellomängija-följetonist Ciqo külmetas kehvas garaažis'),
  ('russian',  'iso-8859-5',  'В чащах юга жил бы цитрус? Да, но фальшивый экземпляр!'),
  ('greek',    'iso-8859-7',  'διαφυλάξτε γενικά τη ζωή σας από βαθειά ψυχικά τραύματα'),
  ('hebrew',   'iso-8859-8',  'עטלף אבק נס דרך מזגן שהתפוצץ כי חם'),
  ('turkish2', 'iso-8859-9',  'Pijamalı hasta yağız şoföre çabucak güvendi.'),
  ('swedish',  'iso-8859-10', 'Flygande bäckasiner söka hwila på mjuka tuvor.'),
  ('thai',     'iso-8859-11', 'เป็นมนุษย์สุดประเสริฐเลิศคุณค่า กว่าบรรดาฝูงสัตว์เดรัจฉาน จงฝ่าฟันพัฒนาวิชาการ อย่าล้างผลาญฤๅเข่นฆ่าบีฑาใคร ไม่ถือโทษโกรธแช่งซัดฮึดฮัดด่า หัดอภัยเหมือนกีฬาอัชฌาสัย ปฏิบัติประพฤติกฎกำหนดใจ พูดจาให้จ๊ะๆ จ๋าๆ น่าฟังเอยฯ'),
  ('polish',   'iso-8859-13', 'Jeżu klątw, spłódź Finom część gry hańb!')
]

with open('test/test.c', 'w') as test:

  test.write('#include <tutf8e.h>\n')
  test.write('\n')
  # for e in sorted(encodings):
  #   name = e.replace('-', '_').lower()
  #   test.write('#include <tutf8e/%s.h>\n'%(name))
  # test.write('\n')

  test.write('#include <stdio.h>\n')
  test.write('#include <string.h>\n')
  test.write('#include <stdlib.h>\n')
  test.write('\n')
  test.write('int main(int argc, char *argv[])\n')
  test.write('{\n')
  test.write('  int pass = 0;\n')
  test.write('  int fail = 0;\n')
  test.write('  int ret;\n')
  test.write('  char *copy;\n')
  test.write('  size_t input_length, output_length;\n')
  test.write('  char buffer[1024];\n')
  # test.write('  char *encoded;\n')
  test.write('\n')

  for i in tests:
    if i[1] in encodings:
      test.write('  static const char %s[] = {\n'%(i[0]))
      data = [i for i in i[2].encode(i[1])] + [ 0 ]
      for i in range(0, len(data), 24):
        test.write('    %s,\n'%(', '.join([ '0x%02x'%(j) for j in data[i:i+24]])))
      test.write('  };\n')

  test.write('\n')
  for i in tests:
    if i[1] in encodings:
      test.write('  static const char %sUTF8[] = {\n'%(i[0]))
      data = [i for i in i[2].encode('utf-8')] + [ 0 ]
      for i in range(0, len(data), 24):
        test.write('    %s,\n'%(', '.join([ '0x%02x'%(j) for j in data[i:i+24]])))
      test.write('  };\n')

  test.write('\n  /* string encode to UTF8, error on invalid input */\n')
  for i in tests:
    if i[1] in encodings:
      name = i[1].replace('-', '_').lower()
      test.write('  output_length = sizeof(buffer);\n')
      test.write('  ret = tutf8e_encoder_string_encode(tutf8e_encoder_%s, %s, NULL, buffer, &output_length);\n'%(name, i[0]))
      test.write('  if (!ret && !strcmp(buffer, %sUTF8)) {\n'%(i[0]))
      test.write('    printf("%s\\n", buffer);\n')
      test.write('    pass++;\n')
      test.write('  } else {\n')
      test.write('    printf("Failed to encode %s test\\n");\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  }\n')
      test.write('\n')

  test.write('\n  /* buffer encode to UTF8, error on invalid input */\n')
  for i in tests:
    if i[1] in encodings:
      name = i[1].replace('-', '_').lower()
      test.write('  input_length = strlen(%s);\n'%(i[0]))
      test.write('  output_length = sizeof(buffer);\n')
      test.write('  ret = tutf8e_encoder_buffer_encode(tutf8e_encoder_%s, %s, input_length, NULL, buffer, &output_length);\n'%(name, i[0]))
      test.write('  if (!ret && (output_length+1)==sizeof(%sUTF8) && !strncmp(buffer, %sUTF8, output_length)) {\n'%(i[0], i[0]))
      test.write('    pass++;\n')
      test.write('  } else {\n')
      test.write('    printf("Failed to encode %s test\\n");\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  }\n')
      test.write('\n')

  test.write('\n  /* string encode to UTF8, first input character invalid -> ? */\n')
  for i in tests:
    if i[1] in ['iso-8859-6', 'iso-8859-7', 'iso-8859-11']:
      name = i[1].replace('-', '_').lower()
      test.write('  output_length = sizeof(buffer);\n')
      test.write('  copy = strdup(%s);\n'%(i[0]))
      test.write('  copy[0] = 255;\n')
      test.write('  buffer[0] = 255;\n')
      test.write('  ret = tutf8e_encoder_string_encode(tutf8e_encoder_%s, copy, "?", buffer, &output_length);\n'%(name))
      test.write('  if (!ret && buffer[0]==\'?\') {\n')
      test.write('    printf("%s\\n", buffer);\n')
      test.write('    pass++;\n')
      test.write('  } else {\n')
      test.write('    printf("Failed to encode %s test\\n");\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  }\n')
      test.write('  free(copy);\n')
      test.write('\n')

  test.write('\n  /* string encode to UTF8, first input character invalid -> [INVALID] */\n')
  for i in tests:
    if i[1] in ['iso-8859-6', 'iso-8859-7', 'iso-8859-11']:
      name = i[1].replace('-', '_').lower()
      test.write('  output_length = sizeof(buffer);\n')
      test.write('  copy = strdup(%s);\n'%(i[0]))
      test.write('  copy[0] = 255;\n')
      test.write('  buffer[0] = 255;\n')
      test.write('  ret = tutf8e_encoder_string_encode(tutf8e_encoder_%s, copy, "[INVALID]", buffer, &output_length);\n'%(name))
      test.write('  if (!ret && !strncmp(buffer, "[INVALID]", 9)) {\n')
      test.write('    printf("%s\\n", buffer);\n')
      test.write('    pass++;\n')
      test.write('  } else {\n')
      test.write('    printf("Failed to encode %s test\\n");\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  }\n')
      test.write('  free(copy);\n')
      test.write('\n')

  test.write('  printf("%d passed, %d failed tests\\n", pass, fail);\n')

  test.write('}\n')
