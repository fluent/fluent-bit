/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/**
 * Test invalid flags
 *
 */


#include <tutf8e.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include  "acutest.h"



/*  
   ca1252: 
 
   char = 129  (8x81) => 0xFFFF
   unicode: 0xc2 0x81
  
   replacement char:
   0xfffd  => 0xef  0xbf  0xbd
*/

/*

  olen = sizeof(buffer);
  ret = tutf8e_encoder_string_encode(tutf8e_encoder_iso_8859_1, english, buffer, &olen, 0);
  if (ret >= 0 && !strcmp(buffer, englishUTF8)) {
    printf("%s\n", buffer);
    pass++;
  } else {
    printf("Failed to encode english test\n");
    fail++;
  }

*/

#define CHR(x) ((unsigned char)((x) & 0xff))


static void test_basic(void) {
    TUTF8encoder encoding;
    int ret;
    size_t olen;
    size_t ilen;
    char ibuf[80];    
    char obuf[80];

    encoding = tutf8e_encoder("windows-1252");

    TEST_CHECK(encoding != NULL);

    ret = tutf8e_string_length(encoding,  "", &ilen, &olen, 0);
    TEST_CHECK(ret == TUTF8E_SAME);
    TEST_CHECK(olen == 0);

    olen = sizeof(obuf);
    ret = tutf8e_string_encode(encoding, "", obuf, &olen, 0);
    TEST_CHECK_(ret == TUTF8E_OK, "ret=%d", ret);
    TEST_CHECK(strcmp("",obuf) == 0);    

    olen = sizeof(obuf);
    ret = tutf8e_string_encode(encoding, "abc", obuf, &olen, 0);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(strcmp("abc",obuf) == 0);

    ibuf[0] = 'a';
    ibuf[1] = CHR(0xe4);  // 'ä'
    ibuf[2] = 0;
    
    olen = sizeof(obuf);
    ret = tutf8e_string_encode(encoding, ibuf, obuf, &olen, 0);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(olen = 3);
}


static void test_toolong(void) {
    TUTF8encoder encoding;
    int ret;
    size_t olen;
    char ibuf[80];
    char obuf[80];
    

    encoding = tutf8e_encoder("windows-1252");

    TEST_CHECK(encoding != NULL);


    ibuf[0] = 'a';
    ibuf[1] = CHR(0xe4);  // 'ä'
    ibuf[2] = 0;

    olen = 2;
    ret = tutf8e_string_encode(encoding, ibuf, obuf, &olen,  0);
    TEST_CHECK(ret == TUTF8E_TOOLONG);
}


static void test_valid(void) {
    TUTF8encoder encoding;
    int ret;
    size_t olen;
    size_t ilen;
    char ibuf[80];
    char obuf[80];
    char tbuf[80];
    
    encoding = tutf8e_encoder("windows-1252");    

    // aä =>  0x61 0xc3 0xc4
    
    ibuf[0] = 'a';
    ibuf[1] = CHR(0xe4);  // 'ä'
    ibuf[2] = 0;

    
    tbuf[0] = 'a';
    tbuf[1] = CHR(0xc3);
    tbuf[2] = CHR(0xa4);
    tbuf[3] = 0;

    ret = tutf8e_string_length(encoding, ibuf, &ilen, &olen, 0);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(ilen == 2);
    TEST_CHECK(olen == 3);

    olen = sizeof(obuf);
    ret = tutf8e_string_encode(encoding, ibuf, obuf,&olen, 0);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(olen == 3);
    TEST_CHECK_(strcmp(obuf,(char*)tbuf) == 0, "(encoding) %s != %s", obuf, tbuf);
}


static void test_inv_keep(void) {
    TUTF8encoder encoding;
    int ret;
    size_t olen;
    size_t ilen;
    char ibuf[80];
    char obuf[80];
    char tbuf[80];
    
    encoding = tutf8e_encoder("windows-1252");    

    // a 0x81  / 129 (euro) => 0xffff
    // encoding: inevalid.
    // char = 129  (8x81) => 0xFFFF
    // direct unicode: 0xc2 0x81    
    
    ibuf[0] = 'a';
    ibuf[1] = CHR(0x81);  // 'ä'
    ibuf[2] = 0;

    
    tbuf[0] = 'a';
    tbuf[1] = CHR(0xc2);
    tbuf[2] = CHR(0x81);
    tbuf[3] = 0;

    // flags = 0 == KEEP
    
    ret = tutf8e_string_length(encoding, ibuf, &ilen, &olen, TUTF8E_FLAG_INV_KEEP);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(ilen == 2);
    TEST_CHECK(olen == 3);

    olen = sizeof(obuf);    
    ret = tutf8e_string_encode(encoding, ibuf, obuf, &olen, TUTF8E_FLAG_INV_KEEP);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(olen == 3);
    TEST_CHECK(strlen(obuf) == 3);
    TEST_CHECK_(strcmp(obuf,(char*)tbuf) == 0, "(encoding) %s != %s", obuf, tbuf);
}


static void test_inv_ignore(void) {
    TUTF8encoder encoding;
    int ret;
    size_t olen;
    size_t ilen;
    char ibuf[80];
    char obuf[80];
    char tbuf[80];
    
    encoding = tutf8e_encoder("windows-1252");    

    // a 0x81  / 129  => 0xffff
    // char = 129  (8x81) => 0xFFFF
    // direct unicode: 0xc2 0x81    
    
    ibuf[0] = 'a';
    ibuf[1] = CHR(0x81);  // euro
    ibuf[2] = 0;

    
    tbuf[0] = 'a';
    tbuf[1] = 0;

    ret = tutf8e_string_length(encoding, ibuf, &ilen, &olen, TUTF8E_FLAG_INV_IGNORE);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(ilen == 2);
    TEST_CHECK(olen == 1);

    olen = sizeof(obuf);
    ret = tutf8e_string_encode(encoding, ibuf, obuf, &olen, TUTF8E_FLAG_INV_IGNORE);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(olen == 1);
    TEST_CHECK(strlen(obuf) == 1);
    TEST_CHECK_(strcmp(obuf,(char*)tbuf) == 0, "() %s != %s", obuf, tbuf);
}

static void test_inv_fail(void) {
    TUTF8encoder encoding;
    int ret;
    size_t olen;
    size_t ilen;
    char ibuf[80];
    char obuf[80];
    
    encoding = tutf8e_encoder("windows-1252");    

    // a 0x81  / 129  => 0xffff
    // char = 129  (8x81) => 0xFFFF
    // direct unicode: 0xc2 0x81    
    
    ibuf[0] = 'a';
    ibuf[1] = CHR(0x81);  // euro
    ibuf[2] = 0;

    
    ret = tutf8e_string_length(encoding, ibuf, &ilen, &olen, TUTF8E_FLAG_INV_FAIL);
    TEST_CHECK(ret == TUTF8E_INVALID);

    olen = sizeof(obuf);
    ret = tutf8e_string_encode(encoding, ibuf, obuf, &olen, TUTF8E_FLAG_INV_FAIL);
    TEST_CHECK(ret == TUTF8E_INVALID);    
}




static void test_inv_question(void) {
    TUTF8encoder encoding;
    int ret;
    size_t olen;
    size_t ilen;
    size_t tlen;
    char ibuf[80];
    char obuf[80];
    char tbuf[80];
    
    encoding = tutf8e_encoder("windows-1252");    

    // a 0x81  / 129  => 0xffff
    // char = 129  (8x81) => 0xFFFF
    // direct unicode: 0xc2 0x81    
    
    ibuf[0] = 'a';
    ibuf[1] = CHR(0x81);  // euro
    ibuf[2] = 0;

    
    tbuf[0] = 'a';
    tbuf[1] = '?';
    tbuf[2] = 0;

    tlen = strlen(tbuf);
    

    ret = tutf8e_string_length(encoding, ibuf, &ilen, &olen, TUTF8E_FLAG_INV_QUESTION);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(ilen == 2);
    TEST_CHECK(olen == 2);

    olen++;  /* room for nul */
    ret = tutf8e_string_encode(encoding, ibuf, obuf, &olen, TUTF8E_FLAG_INV_QUESTION);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(olen == 2);
    TEST_CHECK(strlen(obuf) == 2);
    TEST_CHECK_(strcmp(obuf,(char*)tbuf) == 0, "() %s != %s", obuf, tbuf);
}


/**
 * unkown char is converted to 0xffff == 0xef, 0xbf, 0xbd (replacement char)
 */
static void test_inv_replacement(void) {
    TUTF8encoder encoding;
    int ret;
    size_t olen;
    size_t ilen;
    size_t tlen;
    char ibuf[80];
    char obuf[80];
    char tbuf[80];
    
    encoding = tutf8e_encoder("windows-1252");    

    // a 0x81  / 129  => 0xffff
    // char = 129  (8x81) => 0xFFFF
    // direct unicode: 0xc2 0x81
    // replacement 0xfffd => 0xef  0xbf  0xbd
    
    ibuf[0] = 'a';
    ibuf[1] = CHR(0x81);  // euro
    ibuf[2] = 0;

    
    tbuf[0] = 'a';
    tbuf[1] = CHR(0xef); 
    tbuf[2] = CHR(0xbf);
    tbuf[3] = CHR(0xbd);
    tbuf[4] = 0;

    tlen = strlen(tbuf);
    ret = tutf8e_string_length(encoding, ibuf, &ilen, &olen, TUTF8E_FLAG_INV_REPLACEMENT);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(ilen == 2);
    TEST_CHECK(olen == 4);

    olen++;
    ret = tutf8e_string_encode(encoding, ibuf, obuf, &olen, TUTF8E_FLAG_INV_REPLACEMENT);
    TEST_CHECK(ret == TUTF8E_OK);
    TEST_CHECK(olen == 4);    
    TEST_CHECK(strlen(obuf) == 4);
    TEST_CHECK_(strcmp(obuf,(char*)tbuf) == 0, "() %s != %s", obuf, tbuf);
}


    

TEST_LIST = {
             { "test-basic",            test_basic }, 
             { "test-valid",            test_valid },
             { "test-toolong",          test_toolong },
             { "test-inv-keep",         test_inv_keep },
             { "test-inv-ignore",       test_inv_ignore },
             { "test-inv-fail",         test_inv_fail },
             { "test-inv-replacement",  test_inv_replacement },
             { "test-inv-question",     test_inv_question },
             { NULL }
};
  
