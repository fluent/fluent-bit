/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include "bh_platform.h"
#include "runtime_lib.h"
#include "native_interface.h"
#include "app_manager_export.h"
#include "board_config.h"
#include "bh_platform.h"
#include "runtime_sensor.h"
#include "bi-inc/attr_container.h"
#include "module_wasm_app.h"
#include "wasm_export.h"
#include "sensor_native_api.h"
#include "connection_native_api.h"
#include "display_indev.h"

#if KERNEL_VERSION_NUMBER < 0x030200 /* version 3.2.0 */
#include <zephyr.h>
#else
#include <zephyr/kernel.h>
#endif

#include <drivers/uart.h>
#include <device.h>

extern bool
init_sensor_framework();
extern void
exit_sensor_framework();
extern int
aee_host_msg_callback(void *msg, uint32_t msg_len);

int uart_char_cnt = 0;

static void
uart_irq_callback(const struct device *dev, void *user_data)
{
    unsigned char ch;

    while (uart_poll_in(dev, &ch) == 0) {
        uart_char_cnt++;
        aee_host_msg_callback(&ch, 1);
    }
    (void)user_data;
}

const struct device *uart_dev = NULL;

static bool
host_init()
{
    uart_dev = device_get_binding(HOST_DEVICE_COMM_UART_NAME);
    if (!uart_dev) {
        printf("UART: Device driver not found.\n");
        return false;
    }
    uart_irq_rx_enable(uart_dev);
    uart_irq_callback_set(uart_dev, uart_irq_callback);
    return true;
}

int
host_send(void *ctx, const char *buf, int size)
{
    if (!uart_dev)
        return 0;

    for (int i = 0; i < size; i++)
        uart_poll_out(uart_dev, buf[i]);

    return size;
}

void
host_destroy()
{}

/* clang-format off */
host_interface interface = {
    .init = host_init,
    .send = host_send,
    .destroy = host_destroy
};
/* clang-format on */

timer_ctx_t timer_ctx;

static char global_heap_buf[350 * 1024] = { 0 };

static NativeSymbol native_symbols[] = {
    EXPORT_WASM_API_WITH_SIG(display_input_read, "(*)i"),
    EXPORT_WASM_API_WITH_SIG(display_flush, "(iiii*)"),
    EXPORT_WASM_API_WITH_SIG(display_fill, "(iiii*)"),
    EXPORT_WASM_API_WITH_SIG(display_vdb_write, "(*iii*i)"),
    EXPORT_WASM_API_WITH_SIG(display_map, "(iiii*)"),
    EXPORT_WASM_API_WITH_SIG(time_get_ms, "()i")
};

int
iwasm_main()
{
    RuntimeInitArgs init_args;

    host_init();

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

    init_args.native_module_name = "env";
    init_args.n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
    init_args.native_symbols = native_symbols;

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return -1;
    }

    display_init();

    /* timer manager */
    if (!init_wasm_timer()) {
        goto fail;
    }

    app_manager_startup(&interface);

fail:
    wasm_runtime_destroy();
    return -1;
}
