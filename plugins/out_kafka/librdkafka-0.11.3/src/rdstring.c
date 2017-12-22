/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2016 Magnus Edenhill
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


#include "rd.h"
#include "rdstring.h"

/**
 * @brief Render string \p template using \p callback for key lookups.
 *
 * Keys in template follow the %{keyname} syntax.
 *
 * The \p callback must not write more than \p size bytes to \p buf, must
 * should return the number of bytes it wanted to write (which will indicate
 * a truncated write).
 * If the key is not found -1 should be returned (which fails the rendering).
 *
 * @returns number of written bytes to \p dest,
 *          or -1 on failure (errstr is written)
 */
char *rd_string_render (const char *template,
			char *errstr, size_t errstr_size,
			ssize_t (*callback) (const char *key,
					     char *buf, size_t size,
					     void *opaque),
			 void *opaque) {
	const char *s = template;
	const char *tend = template + strlen(template);
	size_t size = 256;
	char *buf;
	size_t of = 0;

	buf = rd_malloc(size);

#define _remain() (size - of - 1)
#define _assure_space(SZ) do {				\
		if (of + (SZ) + 1 >= size) {		\
			size = (size + (SZ) + 1) * 2;	\
			buf = realloc(buf, size);	\
		}					\
	} while (0)
	
#define _do_write(PTR,SZ) do {				\
		_assure_space(SZ);			\
		memcpy(buf+of, (PTR), (SZ));		\
		of += (SZ);				\
	} while (0)



	while (*s) {
		const char *t;
		size_t tof = (size_t)(s-template);

		t = strstr(s, "%{");
		if (t != s) {
			/* Write "abc%{" 
			 *        ^^^ */
			size_t len = (size_t)((t ? t : tend)-s);
			if (len)
				_do_write(s, len);
		}

		if (t) {
			const char *te;
			ssize_t r;
			char *tmpkey;

			/* Find "abc%{key}"
			 *               ^ */
			te = strchr(t+2, '}');
			if (!te) {
				rd_snprintf(errstr, errstr_size,
					    "Missing close-brace } for "
					    "%.*s at %"PRIusz,
					    15, t, tof);
				rd_free(buf);
				return NULL;
			}

			rd_strndupa(&tmpkey, t+2, (int)(te-t-2));

			/* Query callback for length of key's value. */
			r = callback(tmpkey, NULL, 0, opaque);
			if (r == -1) {
				rd_snprintf(errstr, errstr_size,
					    "Property not available: \"%s\"",
					    tmpkey);
				rd_free(buf);
				return NULL;
			}

			_assure_space(r);

			/* Call again now providing a large enough buffer. */
			r = callback(tmpkey, buf+of, _remain(), opaque);
			if (r == -1) {
				rd_snprintf(errstr, errstr_size,
					    "Property not available: "
					    "\"%s\"", tmpkey);
				rd_free(buf);
				return NULL;
			}

			assert(r < (ssize_t)_remain());
			of += r;
			s = te+1;

		} else {
			s = tend;
		}
	}

	buf[of] = '\0';
	return buf;
}




void rd_strtup_destroy (rd_strtup_t *strtup) {
        rd_free(strtup);
}

rd_strtup_t *rd_strtup_new (const char *name, const char *value) {
        size_t name_sz = strlen(name) + 1;
        size_t value_sz = strlen(value) + 1;
        rd_strtup_t *strtup;

        strtup = rd_malloc(sizeof(*strtup) +
                           name_sz + value_sz - 1/*name[1]*/);
        memcpy(strtup->name, name, name_sz);
        strtup->value = &strtup->name[name_sz];
        memcpy(strtup->value, value, value_sz);

        return strtup;
}
