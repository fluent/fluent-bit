/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020, Magnus Edenhill
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

#ifndef _HELPERS_H_
#define _HELPERS_H_

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>


/**
 * Fuzz program helpers
 */

static __attribute__((unused)) uint8_t *read_file(const char *path,
                                                  size_t *sizep) {
        int fd;
        uint8_t *buf;
        struct stat st;

        if ((fd = open(path, O_RDONLY)) == -1) {
                fprintf(stderr, "Failed to open %s: %s\n", path,
                        strerror(errno));
                exit(2);
                return NULL; /* NOTREACHED */
        }

        if (fstat(fd, &st) == -1) {
                fprintf(stderr, "Failed to stat %s: %s\n", path,
                        strerror(errno));
                close(fd);
                exit(2);
                return NULL; /* NOTREACHED */
        }


        buf = malloc(st.st_size + 1);
        if (!buf) {
                fprintf(stderr, "Failed to malloc %d bytes for %s\n",
                        (int)st.st_size, path);
                close(fd);
                exit(2);
                return NULL; /* NOTREACHED */
        }

        buf[st.st_size] = '\0';

        *sizep = read(fd, buf, st.st_size);
        if (*sizep != st.st_size) {
                fprintf(stderr, "Could only read %d/%d bytes from %s\n",
                        (int)*sizep, (int)st.st_size, path);
                free(buf);
                close(fd);
                exit(2);
                return NULL; /* NOTREACHED */
        }

        return buf;
}


#endif /* _HELPERS_H_ */
