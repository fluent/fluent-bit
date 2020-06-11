/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#define _GNU_SOURCE

#include <monkey/mk_core.h>
#include <monkey/mk_cache.h>
#include <monkey/mk_cache_tls.h>
#include <monkey/mk_config.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_tls.h>

/* This function is called when a thread is created */
void mk_cache_worker_init()
{
    char *cache_error;
    mk_ptr_t *p_tmp;

    /* Cache header request -> last modified */
    p_tmp = mk_mem_alloc_z(sizeof(mk_ptr_t));
    p_tmp->data = mk_mem_alloc_z(32);
    p_tmp->len = -1;
    MK_TLS_SET(mk_tls_cache_header_lm, p_tmp);

    /* Cache header request -> content length */
    p_tmp = mk_mem_alloc_z(sizeof(mk_ptr_t));
    p_tmp->data = mk_mem_alloc_z(MK_UTILS_INT2MKP_BUFFER_LEN);
    p_tmp->len = -1;
    MK_TLS_SET(mk_tls_cache_header_cl, p_tmp);

    /* Cache gmtime buffer */
    MK_TLS_SET(mk_tls_cache_gmtime, mk_mem_alloc(sizeof(struct tm)));

    /* Cache the most used text representations of utime2gmt */
    MK_TLS_SET(mk_tls_cache_gmtext,
                  mk_mem_alloc_z(sizeof(struct mk_gmt_cache) * MK_GMT_CACHES));

    /* Cache buffer for strerror_r(2) */
    cache_error = mk_mem_alloc(MK_UTILS_ERROR_SIZE);
    pthread_setspecific(mk_utils_error_key, (void *) cache_error);
}

void mk_cache_worker_exit()
{
    char *cache_error;

    /* Cache header request -> last modified */
    mk_ptr_free(MK_TLS_GET(mk_tls_cache_header_lm));
    mk_mem_free(MK_TLS_GET(mk_tls_cache_header_lm));

    /* Cache header request -> content length */
    mk_ptr_free(MK_TLS_GET(mk_tls_cache_header_cl));
    mk_mem_free(MK_TLS_GET(mk_tls_cache_header_cl));

    /* Cache gmtime buffer */
    mk_mem_free(MK_TLS_GET(mk_tls_cache_gmtime));

    /* Cache the most used text representations of utime2gmt */
    mk_mem_free(MK_TLS_GET(mk_tls_cache_gmtext));

    /* Cache buffer for strerror_r(2) */
    cache_error = pthread_getspecific(mk_utils_error_key);
    mk_mem_free(cache_error);
}
