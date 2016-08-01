/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef FLB_SHA1_EXT_H
#define FLB_SHA1_EXT_H

typedef struct {
	unsigned long long size;
	unsigned int H[5];
	unsigned int W[16];
} blk_SHA_CTX;

void blk_SHA1_Init(blk_SHA_CTX *ctx);
void blk_SHA1_Update(blk_SHA_CTX *ctx, const void *dataIn, unsigned long len);
void blk_SHA1_Final(unsigned char hashout[20], blk_SHA_CTX *ctx);

#define SHA_CTX	    blk_SHA_CTX
#define SHA1_Init	blk_SHA1_Init
#define SHA1_Update	blk_SHA1_Update
#define SHA1_Final	blk_SHA1_Final

#endif
