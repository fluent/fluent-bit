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
#include "rdunittest.h"

#include <ctype.h>


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
			buf = rd_realloc(buf, size);	\
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

void rd_strtup_free (void *strtup) {
        rd_strtup_destroy((rd_strtup_t *)strtup);
}

rd_strtup_t *rd_strtup_new0 (const char *name, ssize_t name_len,
                             const char *value, ssize_t value_len) {
        rd_strtup_t *strtup;

        /* Calculate lengths, if needed, and add space for \0 nul */

        if (name_len == -1)
                name_len = strlen(name);

        if (!value)
                value_len = 0;
        else if (value_len == -1)
                value_len = strlen(value);


        strtup = rd_malloc(sizeof(*strtup) +
                           name_len + 1 + value_len + 1 - 1/*name[1]*/);
        memcpy(strtup->name, name, name_len);
        strtup->name[name_len] = '\0';
        if (value) {
                strtup->value = &strtup->name[name_len+1];
                memcpy(strtup->value, value, value_len);
                strtup->value[value_len] = '\0';
        } else {
                strtup->value = NULL;
        }

        return strtup;
}

rd_strtup_t *rd_strtup_new (const char *name, const char *value) {
        return rd_strtup_new0(name, -1, value, -1);
}


/**
 * @returns a new copy of \p src
 */
rd_strtup_t *rd_strtup_dup (const rd_strtup_t *src) {
        return rd_strtup_new(src->name, src->value);
}

/**
 * @brief Wrapper for rd_strtup_dup() suitable rd_list_copy*() use
 */
void *rd_strtup_list_copy (const void *elem, void *opaque) {
        const rd_strtup_t *src = elem;
        return (void *)rd_strtup_dup(src);
}



/**
 * @brief Convert bit-flags in \p flags to human-readable CSV string
 *        use the bit-description strings in \p desc.
 *
 *        \p desc array element N corresponds to bit (1<<N).
 *        \p desc MUST be terminated by a NULL array element.
 *        Empty descriptions are ignored even if the bit is set.
 *
 * @returns a null-terminated \p dst
 */
char *rd_flags2str (char *dst, size_t size,
                    const char **desc, int flags) {
        int bit = 0;
        size_t of = 0;

        for ( ; *desc ; desc++, bit++) {
                int r;

                if (!(flags & (1 << bit)) || !*desc)
                        continue;

                if (of >= size) {
                        /* Dest buffer too small, indicate truncation */
                        if (size > 3)
                                rd_snprintf(dst+(size-3), 3, "..");
                        break;
                }

                r = rd_snprintf(dst+of, size-of, "%s%s",
                                !of ? "" : ",", *desc);

                of += r;
        }

        if (of == 0 && size > 0)
                *dst = '\0';

        return dst;
}



/**
 * @returns a djb2 hash of \p str.
 *
 * @param len If -1 the \p str will be hashed until nul is encountered,
 *            else up to the \p len.
 */
unsigned int rd_string_hash (const char *str, ssize_t len) {
        unsigned int hash = 5381;
        ssize_t i;

        if (len == -1) {
                for (i = 0 ; str[i] != '\0' ; i++)
                        hash = ((hash << 5) + hash) + str[i];
        } else {
                for (i = 0 ; i < len ; i++)
                        hash = ((hash << 5) + hash) + str[i];
        }

        return hash;
}


/**
 * @brief Same as strcmp() but handles NULL values.
 */
int rd_strcmp (const char *a, const char *b) {
        if (a == b)
                return 0;
        else if (!a && b)
                return -1;
        else if (!b)
                return 1;
        else
                return strcmp(a, b);
}



/**
 * @brief Case-insensitive strstr() for platforms where strcasestr()
 *        is not available.
 */
char *_rd_strcasestr (const char *haystack, const char *needle) {
        const char *h_rem, *n_last;
        size_t h_len = strlen(haystack);
        size_t n_len = strlen(needle);


        if (n_len == 0 || n_len > h_len)
                return NULL;
        else if (n_len == h_len)
                return !rd_strcasecmp(haystack, needle) ?
                        (char *)haystack : NULL;

        /*
         * Scan inspired by Boyer-Moore:
         *
         * haystack = "this is a haystack"
         * needle   = "hays"
         *
         * "this is a haystack"
         *     ^             ^- h_last
         *     `-h  (haystack + strlen(needle) - 1)
         *     `-h_rem
         *
         * "hays"
         *     ^-n
         *     ^-n_last
         */
        n_last = needle + n_len - 1;
        h_rem = haystack + n_len - 1;

        while (*h_rem) {
                const char *h, *n = n_last;

                /* Find first occurrence of last character in the needle
                   in the remaining haystack. */
                for (h = h_rem ;
                     *h && tolower((int)*h) != tolower((int)*n) ;
                     h++)
                        ;

                if (!*h)
                        return NULL; /* No match */

                /* Backtrack both needle and haystack as long as each character
                 * matches, if the start of the needle is found we have
                 * a full match, else start over from the remaining part of the
                 * haystack. */
                do {
                        if (n == needle)
                                return (char *)h; /* Full match */

                        /* Rewind both n and h */
                        n--;
                        h--;

                } while (tolower((int)*n) == tolower((int)*h));

                /* Mismatch, start over at the next haystack position */
                h_rem++;
        }

        return NULL;
}



/**
 * @brief Unittests for rd_strcasestr()
 */
static int ut_strcasestr (void) {
        static const struct {
                const char *haystack;
                const char *needle;
                ssize_t exp;
        } strs[] = {
                { "this is a haystack", "hays", 10 },
                { "abc", "a", 0 },
                { "abc", "b", 1 },
                { "abc", "c", 2 },
                { "AbcaBcabC", "ABC", 0 },
                { "abcabcaBC", "BcA", 1 },
                { "abcabcABc", "cAB", 2 },
                { "need to estart stART the tart ReStArT!", "REsTaRt", 30 },
                { "need to estart stART the tart ReStArT!", "?sTaRt", -1 },
                { "aaaabaaAb", "ab", 3 },
                { "0A!", "a", 1 },
                { "a", "A", 0 },
                { ".z", "Z", 1 },
                { "", "", -1 },
                { "", "a", -1 },
                { "a", "", -1 },
                { "peRfeCt", "peRfeCt", 0 },
                { "perfect", "perfect", 0 },
                { "PERFECT", "perfect", 0 },
                { NULL },
        };
        int i;

        RD_UT_BEGIN();

        for (i = 0 ; strs[i].haystack ; i++) {
                const char *ret;
                ssize_t of = -1;

                ret = _rd_strcasestr(strs[i].haystack, strs[i].needle);
                if (ret)
                        of = ret - strs[i].haystack;
                RD_UT_ASSERT(of == strs[i].exp,
                             "#%d: '%s' in '%s': expected offset %"PRIdsz
                             ", not %"PRIdsz" (%s)",
                             i, strs[i].needle, strs[i].haystack,
                             strs[i].exp, of, ret ? ret : "(NULL)");
        }

        return 0;
}


/**
 * @brief Unittests for strings
 */
int unittest_string (void) {
        int fails = 0;

        fails += ut_strcasestr();

        return fails;
}
