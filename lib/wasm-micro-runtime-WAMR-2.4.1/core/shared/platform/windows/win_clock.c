/*
 * Copyright (C) 2023 Amazon Inc.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_extension.h"
#include <winternl.h>
#include "win_util.h"

#define NANOSECONDS_PER_SECOND 1000000000ULL
#define NANOSECONDS_PER_TICK 100

#if WINAPI_PARTITION_DESKTOP
#ifndef __kernel_entry
#define __kernel_entry
#endif
#ifndef NTAPI
#define NTAPI
#endif
#ifndef _Out_
#define _Out_
#endif
extern __kernel_entry NTSTATUS NTAPI
NtQueryTimerResolution(_Out_ PULONG MinimumResolution,
                       _Out_ PULONG MaximumResolution,
                       _Out_ PULONG CurrentResolution);
#endif

static __wasi_errno_t
calculate_monotonic_clock_frequency(uint64 *out_frequency)
{
    LARGE_INTEGER frequency;
    if (!QueryPerformanceFrequency(&frequency))
        return convert_windows_error_code(GetLastError());

    *out_frequency = (uint64)frequency.QuadPart;
    return __WASI_ESUCCESS;
}

static __wasi_errno_t
get_performance_counter_value(uint64 *out_counter)
{
    LARGE_INTEGER counter;
    if (!QueryPerformanceCounter(&counter))
        return convert_windows_error_code(GetLastError());

    *out_counter = counter.QuadPart;
    return __WASI_ESUCCESS;
}

__wasi_errno_t
os_clock_res_get(__wasi_clockid_t clock_id, __wasi_timestamp_t *resolution)
{
    __wasi_errno_t error = __WASI_ESUCCESS;

    switch (clock_id) {
        case __WASI_CLOCK_MONOTONIC:
        {
            uint64 frequency;
            error = calculate_monotonic_clock_frequency(&frequency);

            if (error != __WASI_ESUCCESS)
                return error;

            const uint64 result = (uint64)NANOSECONDS_PER_SECOND / frequency;
            *resolution = result;
            return error;
        }
        case __WASI_CLOCK_REALTIME:
        case __WASI_CLOCK_PROCESS_CPUTIME_ID:
        case __WASI_CLOCK_THREAD_CPUTIME_ID:
        {
#if WINAPI_PARTITION_DESKTOP && WASM_ENABLE_WAMR_COMPILER == 0
            ULONG maximum_time;
            ULONG minimum_time;
            ULONG current_time;
            NTSTATUS
            status = NtQueryTimerResolution(&maximum_time, &minimum_time,
                                            &current_time);
            uint64 result = (uint64)current_time * NANOSECONDS_PER_TICK;
            *resolution = result / (uint64)NANOSECONDS_PER_SECOND;
            return error;
#else
            return __WASI_ENOTSUP;
#endif
        }
        default:
            return __WASI_EINVAL;
    }
}

__wasi_errno_t
os_clock_time_get(__wasi_clockid_t clock_id, __wasi_timestamp_t precision,
                  __wasi_timestamp_t *time)
{
    __wasi_errno_t error = __WASI_ESUCCESS;

    switch (clock_id) {
        case __WASI_CLOCK_REALTIME:
        {
            FILETIME sys_now;
#if NTDDI_VERSION >= NTDDI_WIN8
            GetSystemTimePreciseAsFileTime(&sys_now);
#else
            GetSystemTimeAsFileTime(&sys_now);
#endif
            *time = convert_filetime_to_wasi_timestamp(&sys_now);
            return BHT_OK;
        }
        case __WASI_CLOCK_MONOTONIC:
        {
            uint64 frequency;
            error = calculate_monotonic_clock_frequency(&frequency);

            if (error != __WASI_ESUCCESS)
                return error;

            uint64 counter;
            error = get_performance_counter_value(&counter);

            if (error != __WASI_ESUCCESS)
                return error;

            if (NANOSECONDS_PER_SECOND % frequency == 0) {
                *time = counter * NANOSECONDS_PER_SECOND / frequency;
            }
            else {
                uint64 seconds = counter / frequency;
                uint64 fractions = counter % frequency;
                *time = seconds * NANOSECONDS_PER_SECOND
                        + (fractions * NANOSECONDS_PER_SECOND) / frequency;
            }
            return error;
        }
        case __WASI_CLOCK_PROCESS_CPUTIME_ID:
        case __WASI_CLOCK_THREAD_CPUTIME_ID:
        {
            FILETIME creation_time;
            FILETIME exit_time;
            FILETIME kernel_time;
            FILETIME user_time;

            HANDLE handle = (clock_id == __WASI_CLOCK_PROCESS_CPUTIME_ID)
                                ? GetCurrentProcess()
                                : GetCurrentThread();

            if (!GetProcessTimes(handle, &creation_time, &exit_time,
                                 &kernel_time, &user_time))
                return convert_windows_error_code(GetLastError());

            *time = convert_filetime_to_wasi_timestamp(&kernel_time)
                    + convert_filetime_to_wasi_timestamp(&user_time);

            return error;
        }
        default:
            return __WASI_EINVAL;
    }
}
