/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#ifndef FLB_VERSION_H
#define FLB_VERSION_H

/* Helpers to convert/format version string */
#define STR_HELPER(s)      #s
#define STR(s)             STR_HELPER(s)

/* Fluent Bit Version */
#define __FLB__             0
#define __FLB_MINOR__       2
#define __FLB_PATCHLEVEL__  0


/* Macros really used by Fluent Bit core */
#define FLB_VERSION (                           \
                     __FLB__ * 10000            \
                     __FLB_MINOR__ * 100        \
                     __FLB_PATCHLEVEL__)
#define FLB_VERSION_STR  STR(__FLB__) "." STR(__FLB_MINOR__) "." STR(__FLB_PATCHLEVEL__)

#endif
