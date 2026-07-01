/*
 * Copyright (C) 2023 Amazon Inc.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _WIN_UTIL_H
#define _WIN_UTIL_H

#include "platform_wasi_types.h"
/*
 * Suppress the noisy warnings:
 * winbase.h: warning C5105: macro expansion producing 'defined' has
 * undefined behavior
 */
#pragma warning(disable : 5105)
#include <windows.h>

__wasi_timestamp_t
convert_filetime_to_wasi_timestamp(LPFILETIME filetime);

FILETIME
convert_wasi_timestamp_to_filetime(__wasi_timestamp_t timestamp);

/* Convert a Windows error code to a WASI error code */
__wasi_errno_t
convert_windows_error_code(DWORD windows_error_code);

/* Convert a Winsock error code to a WASI error code */
__wasi_errno_t
convert_winsock_error_code(int error_code);

#endif /* end of _WIN_UTIL_H */
