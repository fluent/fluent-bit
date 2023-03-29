/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CFL
 *  ===
 *  Copyright (C) 2022 The CFL Authors
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

/*
 * This file contains compatibility functions and macros for various platforms.
 *
 * Including this header file should make platforms behave more consistently;
 * Add more macros if you find any missing features.
 */

#ifndef CFL_COMPAT_H
#define CFL_COMPAT_H

#ifdef CFL_SYSTEM_WINDOWS

#ifdef _MSC_VER
/*
 * cl.exe that is one of the C++ compilers for Windows prefers
 * to add an underscore to each POSIX function.
 * To suppress compiler warnings, we need these trivial macros.
 * For MSYS2 platform on Windows, we don't need to do.
 */
#define timezone _timezone
#define tzname _tzname
#define strncasecmp _strnicmp
#define timegm _mkgmtime
#endif /* _MSC_VER */

#endif
#endif
