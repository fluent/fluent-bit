/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <iconv.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_iconv.h>
#include <fluent-bit/flb_mem.h>

struct flb_iconv *flb_iconv_open(char *to, char *from) {
    iconv_t ic;
    struct flb_iconv *c;
    ic = iconv_open(to,from);
    if (ic == (iconv_t) -1) {
        return NULL;
    }
    c = flb_calloc(sizeof(struct flb_iconv),1);
    c->conv = ic;
    return c;
}

void flb_iconv_close(struct flb_iconv *c) {
    if(c) {
        iconv_close(c->conv);
        flb_free(c);
    }
}


int flb_iconv_execute(struct flb_iconv *c,
                      char *str, size_t slen,
                      char **result, size_t *result_len,
                      unsigned int flags)
{
    char *outbuf;
    char *inp;
    char *outp;
    size_t outlen;
    size_t outroom;
    size_t outleft;
    size_t ret;
    size_t inleft;
    size_t outdone;

    if(slen == 0) {
        if(flags & FLB_ICONV_ACCEPT_NOT_CHANGED) {
            *result = NULL;
            *result_len = 0;
            return FLB_ICONV_NOT_CHANGED;
        } else {
            outp = flb_malloc(1);
            if(outp == NULL) {
                return FLB_ICONV_FAILURE;
            }
            *result = outp;
            *result_len = 0;
            return FLB_ICONV_SUCCESS;
        }
    }

    inp = str;
    inleft = slen;
    
    outroom = slen + (slen / 2) + 3;  // just add something
    outbuf = flb_malloc(outroom);
    if(outbuf == NULL) {
        return FLB_ICONV_FAILURE;
    }
    outp = outbuf;
    outlen = 0;
    outleft = outroom - 1;

    iconv(c->conv, NULL, NULL, NULL, NULL);

    while(inleft > 0) {
        ret = iconv(c->conv, &inp, &inleft, &outp, &outleft);
        if(ret == -1) {
            switch(errno) {
            case EILSEQ:  // bad input sequence of char (ignore)
                flb_warn("[flb_iconv] bad input char 0x%02x", *inp & 0xff);
                inp++;
                inleft--;
                break;
            case EINVAL:  // imcomplete char (ignore)
                flb_warn("[flb_iconv] incomplete char 0x%02x", *inp & 0xff);
                inp++;
                inleft--;
                break;
                
            case E2BIG:
                outdone = outp - outbuf;
                outroom = outroom * 2;
                outbuf = flb_realloc(outbuf, outroom);
                if(outbuf == NULL) {
                    return FLB_ICONV_FAILURE;
                }
                outp = outbuf + outdone;
                outleft = outroom - outdone - 1;
                break;
            default:
                flb_error("[flb_iconv] unknown error: %d", errno);
                break;
            }
        } else {
            break;
        }
    }
    outdone = outp - outbuf;
    if((flags & FLB_ICONV_ACCEPT_NOT_CHANGED) && (slen == outdone) && (memcmp(str,outbuf,slen) == 0)) {
        flb_free(outbuf);
        *result = NULL;
        *result_len = 0;
        return FLB_ICONV_NOT_CHANGED;
    } else {
        *result = outbuf;
        *result_len = outdone;
        return FLB_ICONV_SUCCESS;
    }
}
    
