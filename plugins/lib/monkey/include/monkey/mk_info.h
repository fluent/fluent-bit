/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#ifndef MK_INFO_H
#define MK_INFO_H

#include <monkey/mk_core.h>

/* Monkey Version */
#define MK_VERSION_MAJOR   1
#define MK_VERSION_MINOR   8
#define MK_VERSION_PATCH   2
#define MK_VERSION         (MK_VERSION_MAJOR * 10000 \
                            MK_VERSION_MINOR * 100   \
                            MK_VERSION_PATCH)
#define MK_VERSION_STR     "1.8.2"

/* Build system information */
#define MK_BUILD_OS        "Darwin"
#define MK_BUILD_UNAME     "Darwin-23.1.0"
#define MK_BUILD_CMD       ""

/* Default paths */
#define MK_PATH_CONF       ""
#define MK_PLUGIN_DIR      "/home/edsiper/coding/monkey/plugins"

/* General flags set by CMakeLists.txt */
#ifndef MK_HAVE_BACKTRACE
#define MK_HAVE_BACKTRACE
#endif
#ifndef MK_HAVE_REGEX
#define MK_HAVE_REGEX
#endif

#endif
