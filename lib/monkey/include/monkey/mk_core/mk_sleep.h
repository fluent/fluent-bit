/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#ifndef MK_SLEEP_H
#define MK_SLEEP_H

#include "mk_core_info.h"

#ifdef __GNUC__      /* Heaven */
#include <time.h>
#include <unistd.h>
#else                /* Not Heaven */

/* Nanoseconds to Milliseconds */
#define NANOS_TO_MILLS  1.0/1000000.0

/* WIN32 conversion */
#define sleep(x)         _sleep(x * 1000)
#define nanosleep(x,z)   _sleep(x * NANOS_TO_MILLS)

#endif

#endif
