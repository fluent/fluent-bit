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

#include <monkey/mk_info.h>


#ifndef MK_VHOST_TLS_H
#define MK_VHOST_TLS_H

#include <monkey/mk_core.h>

#ifdef MK_HAVE_C_TLS  /* Use Compiler Thread Local Storage (TLS) */

__thread struct mk_list *mk_tls_vhost_fdt;

#else

pthread_key_t mk_tls_vhost_fdt;

#endif /* MK_HAVE_C_TLS  */

#endif /* MK_VHOST_TLS_H */
