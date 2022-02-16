/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <Windows.h>
#include <Shlwapi.h>

struct flb_config;
extern struct flb_config *config;
extern int flb_engine_exit(struct flb_config*);
extern int flb_main(int, char**);

/* Windows Service utils */
#define svc_name "fluent-bit"
static SERVICE_STATUS_HANDLE hstatus;
static int win32_argc;
static char **win32_argv;

/*
 * A Windows Service uses 'C:\Windows\System32' as working directory
 * by default. Here we use a more intuitive default path (where
 * fluent-bit.exe exists).
 */
static int update_default_workdir(void)
{
    char path[MAX_PATH];

    if (win32_argc < 1) {
        return -1;
    }

    if (strcpy_s(path, MAX_PATH, win32_argv[0])) {
        return -1;
    }

    if (!PathRemoveFileSpecA(path)) {
        return -1;
    }

    if (!SetCurrentDirectoryA(path)) {
        return -1;
    }

    return 0;
}

static void svc_notify(DWORD status)
{
    SERVICE_STATUS ss;

    ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ss.dwCurrentState = status;
    ss.dwWin32ExitCode = NO_ERROR;
    ss.dwServiceSpecificExitCode = NO_ERROR;
    ss.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    ss.dwWaitHint = 30000;
    ss.dwCheckPoint = 0;

    /*
     * According to MSDN (SetServiceStatus), accepting control on
     * SERVICE_START_PENDING can crash the service.
     */
    if (status == SERVICE_START_PENDING) {
        ss.dwControlsAccepted = 0;
    }

    SetServiceStatus(hstatus, &ss);
}

static void WINAPI svc_handler(DWORD ctrl)
{
    switch (ctrl)
    {
    case SERVICE_CONTROL_STOP:
        svc_notify(SERVICE_STOP_PENDING);
        flb_engine_exit(config);
        return;
    default:
        break;
    }
}

static void WINAPI svc_main(DWORD svc_argc, LPTSTR *svc_argv)
{
    hstatus = RegisterServiceCtrlHandler(svc_name, svc_handler);
    if (!hstatus) {
        return;
    }

    update_default_workdir();

    svc_notify(SERVICE_START_PENDING);
    flb_main(win32_argc, win32_argv);
    svc_notify(SERVICE_STOPPED);
}

/*
 * Notify SCM that Fluent Bit is running.
 *
 * Note: Call this function in the main execution flow (immediately
 * before the engine is starting).
 */
void win32_started(void)
{
    if (hstatus) {
        svc_notify(SERVICE_RUNNING);
    }
}

static const SERVICE_TABLE_ENTRY svc_table[] = {
    {svc_name, svc_main},
    {NULL, NULL}
};

int win32_main(int argc, char **argv)
{
    win32_argc = argc;
    win32_argv = argv;

    if (StartServiceCtrlDispatcher(svc_table)) {
        return 0;
    }

    if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
        return -1;
    }

    /*
     * If we cannot connect to SCM, we assume that "fluent-bit.exe"
     * was invoked from the command line.
     */
    return flb_main(argc, argv);
}
