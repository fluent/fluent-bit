/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <iphlpapi.h>
#include <stddef.h>
#include "flb_tests_runtime.h"
#include "../../plugins/in_windows_exporter_metrics/we_wmi_tcp.h"

static DWORD fixture_rows;
static int growth_failures;
static int table_calls;
static DWORD api_error;
static int live_table;
static void *guard_allocation;

/* Put the exact requested buffer immediately before an inaccessible page. */
static void *guard_realloc(void *old_buffer, size_t size)
{
    SYSTEM_INFO info;
    size_t committed;
    char *allocation;

    GetSystemInfo(&info);
    committed = (size + info.dwPageSize - 1) / info.dwPageSize * info.dwPageSize;
    allocation = VirtualAlloc(NULL, committed + info.dwPageSize,
                              MEM_RESERVE, PAGE_NOACCESS);
    TEST_ASSERT(allocation != NULL);
    TEST_ASSERT(VirtualAlloc(allocation, committed, MEM_COMMIT, PAGE_READWRITE) != NULL);
    if (guard_allocation != NULL) {
        VirtualFree(guard_allocation, 0, MEM_RELEASE);
    }
    guard_allocation = allocation;
    /* Retries overwrite the table; no previous contents need to be preserved. */
    return allocation + committed - size;
}

static void guard_free(void *buffer)
{
    if (buffer != NULL) {
        TEST_ASSERT(guard_allocation != NULL);
        TEST_CHECK(VirtualFree(guard_allocation, 0, MEM_RELEASE) != 0);
        guard_allocation = NULL;
    }
}

static DWORD WINAPI fixture_tcp_table(PVOID buffer, PDWORD size, BOOL ordered,
                                      ULONG family, TCP_TABLE_CLASS table_class,
                                      ULONG reserved)
{
    PMIB_TCPTABLE_OWNER_PID table4;
    PMIB_TCP6TABLE_OWNER_PID table6;
    DWORD required;
    DWORD i;

    if (live_table) {
        return GetExtendedTcpTable(buffer, size, ordered, family, table_class, reserved);
    }
    TEST_CHECK(table_class == TCP_TABLE_OWNER_PID_ALL);
    TEST_CHECK(family == AF_INET || family == AF_INET6);
    if (family == AF_INET) {
        required = offsetof(MIB_TCPTABLE_OWNER_PID, table) +
                   fixture_rows * sizeof(MIB_TCPROW_OWNER_PID);
    }
    else {
        required = offsetof(MIB_TCP6TABLE_OWNER_PID, table) +
                   fixture_rows * sizeof(MIB_TCP6ROW_OWNER_PID);
    }
    if (buffer == NULL) {
        *size = required;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    table_calls++;
    if (growth_failures > 0) {
        growth_failures--;
        *size += 56;
        return ERROR_INSUFFICIENT_BUFFER;
    }
    if (api_error != NO_ERROR) {
        return api_error;
    }
    TEST_ASSERT(*size >= required);
    memset(buffer, 0xa5, required);
    if (family == AF_INET) {
        table4 = buffer;
        table4->dwNumEntries = fixture_rows;
        for (i = 0; i < fixture_rows; i++) {
            table4->table[i].dwState = i % 13 + 1;
        }
    }
    else {
        table6 = buffer;
        table6->dwNumEntries = fixture_rows;
        for (i = 0; i < fixture_rows; i++) {
            table6->table[i].dwState = i % 13 + 1;
        }
    }
    return NO_ERROR;
}

/* Exercise the private collector with controlled Win32 replies and guard pages. */
#define GetExtendedTcpTable fixture_tcp_table
#define flb_realloc guard_realloc
#define flb_free guard_free
#define TCP_STATE_STRINGS test_tcp_state_strings
#define we_wmi_tcp_init test_tcp_init
#define we_wmi_tcp_update test_tcp_update
#define we_wmi_tcp_exit test_tcp_exit
#include "../../plugins/in_windows_exporter_metrics/we_wmi_tcp.c"
#undef GetExtendedTcpTable
#undef flb_realloc
#undef flb_free

static void check_counts(struct flb_we *ctx, char *family, DWORD rows)
{
    char *states[] = {
        "CLOSE", "LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT1",
        "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT",
        "DELETE_TCB", "UNKNOWN"
    };
    char *labels[2];
    double value;
    unsigned int expected;
    int i;

    labels[0] = family;
    for (i = 0; i < 13; i++) {
        labels[1] = states[i];
        expected = rows / 13 + (i < rows % 13);
        TEST_CHECK(cmt_gauge_get_val(ctx->wmi_tcp->connections_state, 2, labels, &value) == 0);
        TEST_CHECK(value == expected);
        TEST_MSG("%s %s: expected %u, got %.0f", family, states[i], expected, value);
    }
}

static void run_collector_test(char *family, int live)
{
    struct flb_we ctx = {0};
    struct we_wmi_tcp_counters counters = {0};
    struct flb_input_instance ins = {0};
    char *keys[] = {"af", "state"};
    char *labels[] = {family, "LISTEN"};
    WSADATA wsa;
    SOCKET listener = INVALID_SOCKET;
    struct sockaddr_storage address = {0};
    struct sockaddr_in *address4;
    struct sockaddr_in6 *address6;
    int address_size;
    int af;
    double value;

    ctx.ins = &ins;
    ins.log_level = FLB_LOG_OFF;
    ctx.wmi_tcp = &counters;
    ctx.cmt = cmt_create();
    TEST_ASSERT(ctx.cmt != NULL);
    counters.connections_state = cmt_gauge_create(ctx.cmt, "windows", "tcp",
                                                 "connections_state", "TCP states", 2, keys);
    TEST_ASSERT(counters.connections_state != NULL);
    live_table = live;
    fixture_rows = 368;
    growth_failures = 0;
    api_error = NO_ERROR;
    table_calls = 0;

    if (live) {
        TEST_ASSERT(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
        af = strcmp(family, "ipv4") == 0 ? AF_INET : AF_INET6;
        listener = socket(af, SOCK_STREAM, IPPROTO_TCP);
        TEST_ASSERT(listener != INVALID_SOCKET);
        if (af == AF_INET) {
            address4 = (struct sockaddr_in *) &address;
            address4->sin_family = AF_INET;
            address4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address_size = sizeof(*address4);
        }
        else {
            address6 = (struct sockaddr_in6 *) &address;
            address6->sin6_family = AF_INET6;
            address6->sin6_addr.u.Byte[15] = 1;
            address_size = sizeof(*address6);
        }
        TEST_ASSERT(bind(listener, (struct sockaddr *) &address, address_size) == 0);
        TEST_ASSERT(listen(listener, 1) == 0);
    }

    TEST_CHECK(we_tcp_get_state_metrics(&ctx, family) == 0);
    TEST_CHECK(guard_allocation == NULL);
    if (live) {
        TEST_CHECK(cmt_gauge_get_val(counters.connections_state, 2, labels, &value) == 0);
        TEST_CHECK(value >= 1);
        closesocket(listener);
        WSACleanup();
    }
    else {
        check_counts(&ctx, family, fixture_rows);

        /* A growing table succeeds on the final permitted attempt. */
        growth_failures = 2;
        table_calls = 0;
        TEST_CHECK(we_tcp_get_state_metrics(&ctx, family) == 0);
        TEST_CHECK(table_calls == 3);
        check_counts(&ctx, family, fixture_rows);

        /* Failed collections must preserve the last successful values. */
        growth_failures = 10;
        table_calls = 0;
        TEST_CHECK(we_tcp_get_state_metrics(&ctx, family) == -1);
        TEST_CHECK(table_calls == 3);
        TEST_CHECK(guard_allocation == NULL);
        check_counts(&ctx, family, fixture_rows);

        growth_failures = 0;
        api_error = ERROR_ACCESS_DENIED;
        TEST_CHECK(we_tcp_get_state_metrics(&ctx, family) == -1);
        TEST_CHECK(guard_allocation == NULL);
        check_counts(&ctx, family, fixture_rows);
        api_error = NO_ERROR;

        /* An empty successful snapshot clears every previously nonzero state. */
        fixture_rows = 0;
        TEST_CHECK(we_tcp_get_state_metrics(&ctx, family) == 0);
        check_counts(&ctx, family, 0);
    }
    cmt_destroy(ctx.cmt);
}

static void test_ipv4(void)
{
    run_collector_test("ipv4", 0);
}

static void test_ipv6(void)
{
    run_collector_test("ipv6", 0);
}

static void test_live_ipv4(void)
{
    run_collector_test("ipv4", 1);
}

static void test_live_ipv6(void)
{
    run_collector_test("ipv6", 1);
}

TEST_LIST = {
    {"tcp_ipv4_states", test_ipv4},
    {"tcp_ipv6_states", test_ipv6},
    {"tcp_live_ipv4", test_live_ipv4},
    {"tcp_live_ipv6", test_live_ipv6},
    {NULL, NULL}
};
