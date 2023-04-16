/*
 * sockem - socket-level network emulation
 *
 * Copyright (c) 2016, Magnus Edenhill, Andreas Smas
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RD_SOCKEM_H_
#define _RD_SOCKEM_H_

#include <sys/types.h>
#include <sys/socket.h>


typedef struct sockem_s sockem_t;



/**
 * @brief Connect to \p addr
 *
 * See sockem_set for the va-arg list definition.
 *
 * @returns a sockem handle on success or NULL on failure.
 */
sockem_t *
sockem_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen, ...);

/**
 * @brief Close the connection and destroy the sockem.
 */
void sockem_close(sockem_t *skm);



/**
 * @brief Set sockem parameters by `char *key, int val` tuples.
 *
 * Keys:
 *   rx.thruput
 *   tx.thruput
 *   delay
 *   jitter
 *   rx.bufsz
 *   true (dummy, ignored)
 *
 * The key may also be a CSV-list of "key=val,key2=val2" pairs in which case
 * val must be 0 and the sentinel NULL.
 *
 * The va-arg list must be terminated with a NULL sentinel
 *
 * @returns 0 on success or -1 if a key was unknown.
 */
int sockem_set(sockem_t *skm, ...);



/**
 * @brief Find sockem by (application) socket.
 * @remark Application is responsible for locking.
 */
sockem_t *sockem_find(int sockfd);

#endif /* _RD_SOCKEM_H_ */
