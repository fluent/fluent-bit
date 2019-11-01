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

/* Determine the input length and UTF8 encoded length of NUL-terminated input string */
/* return TUTF8E_INVALID if input character is not convertable                       */
/* return TUTF8E_OK for success                                                      */

int tutf8e_string_length(const uint16_t *table, const char *input, size_t *ilen, size_t *olen)
{
  for (const unsigned char *i = (const unsigned char *) input; *i; ++i, (*ilen)++) {
    const uint16_t c = table[*i];
    if (c<0x80) {
      *olen += 1;
      continue;
    }
    if (c<0x800) {
      *olen += 2;
      continue;
    }
    if (c<0xffff) {
      *olen += 3;
      continue;
    }
    return TUTF8E_INVALID;
  }
  return TUTF8E_OK;
}

/* UTF8 encode the given input string and table                */
/* olen input is output buffer size, output is encoded length  */
/* return TUTF8E_TOOLONG if output buffer insuficient          */
/* return TUTF8E_INVALID if input character is not convertable */
/* return TUTF8E_OK for success                                */

int tutf8e_string_encode(const uint16_t *table, const char *i, char *o, size_t *olen)
{
  int ret;
  size_t ilen = 0;
  size_t length = 0;
  if (!(ret = tutf8e_string_length(table, i, &ilen, &length)))
  {
    if (length+1 > *olen) return TUTF8E_TOOLONG;
    if (!(ret = tutf8e_buffer_encode(table, i, ilen, o, olen)))
    {
      o[length] = 0;
      return TUTF8E_OK;
    }
  }
  return ret;
}

/* Determine the length of the UTF8 encoding of given input string and table */
/* return TUTF8E_INVALID if input character is not convertable               */
/* return TUTF8E_OK for success                                              */

int tutf8e_buffer_length(const uint16_t *table, const char *input, size_t ilen, size_t *length)
{
  for (const unsigned char *i = (const unsigned char *) input; ilen; ++i, --ilen) {
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
    return TUTF8E_INVALID;
  }
  return TUTF8E_OK;
}

/* UTF8 encode the given input string and table                */
/* olen input is output buffer size, output is encoded length  */
/* return TUTF8E_TOOLONG if output buffer insuficient          */
/* return TUTF8E_INVALID if input character is not convertable */
/* return TUTF8E_OK for success                                */

int tutf8e_buffer_encode(const uint16_t *table, const char *input, size_t ilen, char *output, size_t *olen)
{
  size_t left = *olen;
  unsigned char *o = (unsigned char *) output;
  for (const unsigned char *i = (const unsigned char *) input; ilen; ++i, --ilen) {
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
    return TUTF8E_INVALID;
  }
  *olen -= left;
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
static inline int tutf8e_%s_string_length(const char *i, size_t *ilen, size_t *olen)
{
  return tutf8e_encoder_string_length(tutf8e_encoder_%s, i, ilen, olen);
}
'''%(name, name))

    include.write('''
static inline int tutf8e_%s_string_encode(const char *i, char *o, size_t *olen)
{
  return tutf8e_encoder_string_encode(tutf8e_encoder_%s, i, o, olen);
}
'''%(name, name))

    include.write('''
static inline int tutf8e_%s_buffer_length(const char *i, size_t ilen, size_t *length)
{
  return tutf8e_encoder_buffer_length(tutf8e_encoder_%s, i, ilen, length);
}
'''%(name, name))

    include.write('''
static inline int tutf8e_%s_buffer_encode(const char *i, size_t ilen, char *o, size_t *olen)
{
  return tutf8e_encoder_buffer_encode(tutf8e_encoder_%s, i, ilen, o, olen);
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
  test.write('  size_t ilen, olen;\n')
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

  test.write('\n  /* string encode to UTF8 */\n')
  for i in tests:
    if i[1] in encodings:
      name = i[1].replace('-', '_').lower()
      test.write('  olen = sizeof(buffer);\n')
      test.write('  ret = tutf8e_encoder_string_encode(tutf8e_encoder_%s, %s, buffer, &olen);\n'%(name, i[0]))
      test.write('  if (!ret && !strcmp(buffer, %sUTF8)) {\n'%(i[0]))
      test.write('    printf("%s\\n", buffer);\n')
      test.write('    pass++;\n')
      test.write('  } else {\n')
      test.write('    printf("Failed to encode %s test\\n");\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  }\n')
      test.write('\n')

  test.write('\n  /* buffer encode to UTF8 */\n')
  for i in tests:
    if i[1] in encodings:
      name = i[1].replace('-', '_').lower()
      test.write('  ilen = strlen(%s);\n'%(i[0]))
      test.write('  olen = sizeof(buffer);\n')
      test.write('  ret = tutf8e_encoder_buffer_encode(tutf8e_encoder_%s, %s, ilen, buffer, &olen);\n'%(name, i[0]))
      test.write('  if (!ret && (olen+1)==sizeof(%sUTF8) && !strncmp(buffer, %sUTF8, olen)) {\n'%(i[0], i[0]))
      test.write('    pass++;\n')
      test.write('  } else {\n')
      test.write('    printf("Failed to encode %s test\\n");\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  }\n')
      test.write('\n')

  test.write('  printf("%d passed, %d failed tests\\n", pass, fail);\n')

  test.write('}\n')
