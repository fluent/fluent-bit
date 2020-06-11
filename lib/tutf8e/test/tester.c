/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <tutf8e.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#define TUTF8E_FLAG_INV_KEEP         0    /* illegal char: keep, just use as unicode codepoint  */
#define TUTF8E_FLAG_INV_FAIL         1    /* illegal char: fail on invalid char */
#define TUTF8E_FLAG_INV_IGNORE       2    /* illegal char: skip/ignore invalid char */
#define TUTF8E_FLAG_INV_REPLACEMENT  3    /* illegal char: convert to replacement character  */
#define TUTF8E_FLAG_INV_QUESTION     4    /* illegal char: convert to '?' */
#define TUTF8E_FLAG_INV_COPY         5    /* illegal char: just copy byte */


//  0xfffd => ef  bf  bd
//  '?' => 0x3f


#define BUFFER_SIZE (4 * 1024)

static char ibuffer[BUFFER_SIZE];
static char obuffer[BUFFER_SIZE];

int main(int argc, char *argv[])
{
    uint32_t flags = 0;
    TUTF8encoder encoder;
    size_t olen;
    int line = 0;
    int ch;
    int ret;
      
    const char *encoder_name = "windows-1252";
    
    while ((ch = getopt(argc, argv, "kfirqc?e:")) != -1) {
        switch (ch) {
        case 'k':  flags = TUTF8E_FLAG_INV_KEEP;   break;
        case 'f':  flags = TUTF8E_FLAG_INV_FAIL;   break;
        case 'i':  flags = TUTF8E_FLAG_INV_IGNORE;   break;
        case 'r':  flags = TUTF8E_FLAG_INV_REPLACEMENT;  break;
        case 'q':  
        case '?':  flags = TUTF8E_FLAG_INV_QUESTION;  break;
        case 'c':  flags = TUTF8E_FLAG_INV_COPY;  break;
        case 'e':
            encoder_name = strdup(optarg);
            break;
        default:
            fprintf(stderr,"illegal code: %c", ch);
        }
    }
    argc -= optind;
    argv += optind;

    encoder = tutf8e_encoder(encoder_name);
    if(!encoder) {
        fprintf(stderr,"no such encoder: '%s'\n", encoder_name);
        exit(1);
    }

    while(fgets(ibuffer,BUFFER_SIZE-1, stdin)) {
        line++;
        olen = BUFFER_SIZE;
        if((ret = tutf8e_string_encode(encoder, ibuffer,  obuffer, &olen, flags)) < 0) {
            fprintf(stderr, "[%d] failed: %d\n", line, ret);
            continue;
        }
        fputs(obuffer,stdout);
    }
}
