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

#ifndef MK_CORE_H
#define MK_CORE_H

#ifdef __cplusplus /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>

#include "mk_core/mk_core_info.h"
#include "mk_core/mk_pthread.h"
#include "mk_core/mk_iov.h"
#include "mk_core/mk_uio.h"
#include "mk_core/mk_list.h"
#include "mk_core/mk_pthread.h"
#include "mk_core/mk_unistd.h"

/* WIN32 */
#ifdef _WIN32
/* Posix function name deprecation warning */
#pragma warning(disable : 4996)
/* Type casting issues, only disabled momentarily*/
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)
#pragma warning(disable : 4133)
#endif

#include "mk_core/mk_getopt.h"
#include "mk_core/mk_pipe.h"
#include "mk_core/mk_sleep.h"
/* --- end --- */

#include "mk_core/mk_memory.h"
#include "mk_core/mk_file.h"
#include "mk_core/mk_event.h"
#include "mk_core/mk_rconf.h"
#include "mk_core/mk_string.h"
#include "mk_core/mk_macros.h"
#include "mk_core/mk_utils.h"
#include "mk_core/mk_unistd.h"

#ifdef __cplusplus /* If this is a C++ compiler, use C linkage */
}
#endif

#endif
