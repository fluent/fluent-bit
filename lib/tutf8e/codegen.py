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


uint32_t tutf8e_encoder_flag(const char *string_flag)
{
  if(string_flag == NULL || *string_flag == 0) {
    return 0;
  }
  switch(*string_flag) {
  case 'f':
    if(!strcmp(string_flag,"fail")) {
      return TUTF8E_FLAG_INV_FAIL;
    }
    break;

  case 'i':
    if(!strcmp(string_flag,"ignore")) {
      return TUTF8E_FLAG_INV_IGNORE;
    }
    break;

  case 'k':
    if(!strcmp(string_flag,"keep")) {
      return TUTF8E_FLAG_INV_KEEP;
    }
    break;

  case 'r':
    if(!strcmp(string_flag,"replacement")) {
      return TUTF8E_FLAG_INV_REPLACEMENT;
    }
    break;

  case 'q':
    if(!strcmp(string_flag,"question")) {
      return TUTF8E_FLAG_INV_QUESTION;
    }
    break;
  default:
    break;
  }
  return (uint32_t)(-1);
}

/* Determine the input length and UTF8 encoded length of NUL-terminated input string */
/* return TUTF8E_INVALID if input character is not convertable  TUTF8E_FLAG_INV_FAIL */
/* return TUTF8E_SAME    if string doesn't need changes */
/* return TUTF8E_OK      if string changes   */


int tutf8e_string_length(const TUTF8encoder encoder, const char *input, size_t *ilen, size_t *olen, uint32_t flags)
{
  const uint16_t *table = (uint16_t *) encoder;
  const unsigned char *i;
  int changed = 0;
  int len = 0;
  for (i = (const unsigned char *) input; *i; ++i) {
    const uint16_t c = table[*i];

    if (c<0x80) {
      len++;
      if(c != *i) changed++;
      continue;
    }
    changed++;
    if (c<0x800) {
      len += 2;
      continue;
    }
    if (c<0xffff) {
      len += 3;
      continue;
    }
    switch(flags & TUTF8E_FLAG_INV_MASK) {
    case TUTF8E_FLAG_INV_KEEP        : len += *i <= 0x80 ? 1 : 2; break;
    case TUTF8E_FLAG_INV_FAIL        : return  TUTF8E_INVALID;
    case TUTF8E_FLAG_INV_IGNORE      : break;
    case TUTF8E_FLAG_INV_REPLACEMENT : len += 3; break;
    case TUTF8E_FLAG_INV_QUESTION    : len++; break;
    case TUTF8E_FLAG_INV_COPY        : len++; break;
    }
  }
  *ilen = (char*)i- (char *)input;
  *olen = len;
  return changed ? TUTF8E_OK : TUTF8E_SAME;
}


/* UTF8 encode the given input string and table                */
/* olen input is output buffer size, output is encoded length  */

/* return TUTF8E_INVALID if input character is not convertable */
/* return >= 0  : length of encoded string */

int tutf8e_string_encode(const TUTF8encoder encoder, const char *input, char *output, size_t *olen, uint32_t flags)
{
  int ret;
  size_t ilen = 0;
  size_t length = 0;

  if ((ret = tutf8e_string_length(encoder, input, &ilen, &length, flags)) < 0) {
    return ret;
  }

  if (length+1 > *olen) return TUTF8E_TOOLONG;

  if ((ret = tutf8e_buffer_encode(encoder, input, ilen, output, olen, flags)) < 0) {
    return ret;
  }

  output[*olen] = 0;

  return TUTF8E_OK;
}

/* Determine the length of the UTF8 encoding of given input string and table */
/* return TUTF8E_INVALID if input character is not convertable               */
/* return TUTF8E_SAME    if string doesn't need change                       */
/* return TUTF8E_OK      if string changes                                   */

int tutf8e_buffer_length(const TUTF8encoder encoder, const char *input, size_t ilen, size_t *olen, uint32_t flags)
{
  const uint16_t *table = (uint16_t *) encoder;
  const unsigned char *i;
  int changed = 0;
  int len = 0;
  for (i = (const unsigned char *) input; ilen; ++i, --ilen) {
    const uint16_t c = table[*i];
    if (c<0x80) {
      len++;
      if(c != *i) changed++;
      continue;
    }
    changed++;
    if (c<0x800) {
      len += 2;
      continue;
    }
    if (c<0xffff) {
      len += 3;
      continue;
    }
    switch(flags & TUTF8E_FLAG_INV_MASK) {
    case TUTF8E_FLAG_INV_KEEP        : len += *i <= 0x80 ? 1 : 2; break;
    case TUTF8E_FLAG_INV_FAIL        : return  TUTF8E_INVALID;
    case TUTF8E_FLAG_INV_IGNORE      : break;
    case TUTF8E_FLAG_INV_REPLACEMENT : len += 3; break;
    case TUTF8E_FLAG_INV_QUESTION    : len++; break;
    case TUTF8E_FLAG_INV_COPY        : len++; break;
    }
  }
  *olen = len;
  return changed ? TUTF8E_OK : TUTF8E_SAME;
}

/* UTF8 encode the given input string and table                */
/* olen input is output buffer size, output is encoded length  */
/* return TUTF8E_INVALID if input character is not convertable */
/* return >= 0 size of encoded string                          */

int tutf8e_buffer_encode(const TUTF8encoder encoder, const char *input, size_t ilen, char *output, size_t *olen, uint32_t flags)
{
  const uint16_t *table = (uint16_t *) encoder;
  unsigned char *o = (unsigned char *) output;
  const unsigned char *i;


  for (i = (const unsigned char *) input; ilen; ++i, --ilen) {
    uint16_t c = table[*i];

    if(c == 0xffff) {
      switch(flags & TUTF8E_FLAG_INV_MASK) {
      case TUTF8E_FLAG_INV_KEEP        : c = *i; break;
      case TUTF8E_FLAG_INV_FAIL        : return TUTF8E_INVALID;
      case TUTF8E_FLAG_INV_IGNORE      : continue;
      case TUTF8E_FLAG_INV_REPLACEMENT : c = (uint16_t) 0xFFFD ; break;
      case TUTF8E_FLAG_INV_QUESTION    : c = (uint16_t) '?'    ; break;
      case TUTF8E_FLAG_INV_COPY        : *(o++) = *i;  continue;
      }
    }

    if (c<0x80) {
      *(o++) = c;
      continue;
    }
    if (c<0x800) {
      *(o++) = 0xc0 | (c>>6);
      *(o++) = 0x80 | (c&0x3f);
      continue;
    }
    *(o++) = 0xe0 | (c>>12);
    *(o++) = 0x80 | ((c>>6)&0x3f);
    *(o++) = 0x80 | (c&0x3f);
  }
  *olen = (char*) o - output;
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
  char last;
  int slen = strlen(encoding);
  if(slen == 0) return NULL;
  last = encoding[slen-1];
''')

  lasts = {}

  for e in sorted(encodings):
    name = e.replace('-', '_').lower()
    lastChar = name[-1]
    if not lastChar in lasts:
      lasts[lastChar] = []
    lasts[lastChar].append((len(name), e , name))

  src.write("  switch(last) {\n")

  for lastChar in lasts:
    codings = lasts[lastChar]
    src.write("    case '%s':\n" % (lastChar))
    for n in codings:
      slen, encoding, name = n
      src.write('    if (slen == %d && !memcmp(encoding, "%s", %d)) return tutf8e_encoder_%s;\n' % (slen, encoding, slen, name))
    src.write('    break;\n\n')
  src.write("    default: break;\n\n")
  src.write("  }\n")
  src.write("  return NULL;\n")
  src.write("}")


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
static inline int tutf8e_%s_string_length(const char *i, size_t *ilen, size_t *olen, uint32_t flags)
{
  return tutf8e_string_length(tutf8e_encoder_%s, i, ilen, olen, flags);
}
'''%(name, name))

    include.write('''
static inline int tutf8e_%s_string_encode(const char *i, char *o, uint32_t flags)
{
  return tutf8e_string_encode(tutf8e_encoder_%s, i, o, flags);
}
'''%(name, name))

    include.write('''
static inline int tutf8e_%s_buffer_length(const char *i, size_t ilen, size_t *length, uint32_t flags)
{
  return tutf8e_buffer_length(tutf8e_encoder_%s, i, ilen, length, flags);
}
'''%(name, name))

    include.write('''
static inline int tutf8e_%s_buffer_encode(const char *i, size_t ilen, char *o, uint32_t flags)
{
  return tutf8e_buffer_encode(tutf8e_encoder_%s, i, ilen, o, olen, flags);
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
  test.write('  size_t ilen;\n')
  test.write('  size_t olen;\n')
  test.write('  size_t xlen;\n')
  test.write('  size_t ylen;\n')

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


  test.write('\n  /* test length function */\n')
  for i in tests:
    if i[1] in encodings:
      name = i[1].replace('-', '_').lower()
      test.write('  xlen = strlen(%s);\n'%(i[0]))
      test.write('  ylen = strlen(%sUTF8);\n'%(i[0]))
      test.write('  olen = sizeof(buffer);\n')
      test.write('  ret = tutf8e_string_length(tutf8e_encoder_%s, %s, &ilen, &olen, 0);\n'%(name, i[0]))
      test.write('  if (ret < 0) {\n')
      test.write('    printf("(length test) %s : got error %%d\\n", ret);\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  } else if(xlen != ilen) {\n');
      test.write('    printf("(length test) %s : ilen wrong %%ld != %%ld\\n", ilen , xlen);\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  } else if(ylen != olen){\n');
      test.write('    printf("(length test) %s : olen wrong %%ld != %%ld\\n", olen , ylen);\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  } else {\n')
      test.write('    printf("(length test) %s : ok\\n");\n'%(i[0]))
      test.write('    pass++;\n')
      test.write('  }\n')
      test.write('\n')


  test.write('\n  /* string encode to UTF8 */\n')
  for i in tests:
    if i[1] in encodings:
      name = i[1].replace('-', '_').lower()
      test.write('  olen = sizeof(buffer);\n')
      test.write('  ret = tutf8e_string_encode(tutf8e_encoder_%s, %s, buffer, &olen, 0);\n'%(name, i[0]))
      test.write('  if (ret >= 0 && !strcmp(buffer, %sUTF8)) {\n'%(i[0]))
      test.write('    printf("(string test) : ok : %s : %%s\\n", buffer);\n' %(i[0]))
      test.write('    pass++;\n')
      test.write('  } else {\n')
      test.write('    printf("(string test) Failed to encode %s test\\n");\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  }\n')
      test.write('\n')

  test.write('\n  /* buffer encode to UTF8 */\n')
  for i in tests:
    if i[1] in encodings:
      name = i[1].replace('-', '_').lower()
      test.write('  ilen = strlen(%s);\n'%(i[0]))
      test.write('  xlen = strlen(%sUTF8);\n'%(i[0]))
      test.write('  ret = tutf8e_buffer_encode(tutf8e_encoder_%s, %s, ilen, buffer, &olen, 0);\n'%(name, i[0]))
      test.write('  if (ret < 0)  {\n')
      test.write('    printf("(buffer test) Failed to encode %s test : ret(%%d)\\n", ret);\n'%(i[0]))
      test.write('  } else if (olen != xlen)  {\n')
      test.write('    printf("(buffer test) Failed to encode %s test : length diff : %%ld != %%ld\\n", olen, xlen);\n'%(i[0]))
      test.write('    fail++;\n')
      test.write('  } else if (strncmp(buffer, %sUTF8, olen)) {\n'%(i[0]))
      test.write('    printf("(buffer test) Failed to encode %s test : output diffs=(%%s) expect(%%s)\\n", buffer, %sUTF8);\n'%(i[0],i[0]))
      test.write('    fail++;\n')
      test.write('  } else {\n')
      test.write('    printf("(buffer test) ok %s\\n");\n'%(i[0]))
      test.write('    pass++;\n')
      test.write('  }\n')
      test.write('\n')

  test.write('  printf("%d passed, %d failed tests\\n", pass, fail);\n')

  test.write('}\n')
