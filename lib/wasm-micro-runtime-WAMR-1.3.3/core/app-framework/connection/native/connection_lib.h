/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef CONNECTION_LIB_H_
#define CONNECTION_LIB_H_

#include "bi-inc/attr_container.h"
#include "wasm_export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This file defines connection library which should be implemented by
 * different platforms
 */

/*
 * @brief Open a connection.
 *
 * @param name name of the connection, "TCP", "UDP" or "UART"
 * @param args connection arguments, such as: ip:127.0.0.1, port:8888
 *
 * @return 0~0xFFFFFFFE means id of the connection, otherwise(-1) means fail
 */
typedef uint32 (*connection_open_f)(wasm_module_inst_t module_inst,
                                    const char *name, attr_container_t *args);

/*
 * @brief Close a connection.
 *
 * @param handle of the connection
 */
typedef void (*connection_close_f)(uint32 handle);

/*
 * @brief Send data to the connection in non-blocking manner.
 *
 * @param handle of the connection
 * @param data data buffer to be sent
 * @param len length of the data in byte
 *
 * @return actual length sent, -1 if fail
 */
typedef int (*connection_send_f)(uint32 handle, const char *data, int len);

/*
 * @brief Configure connection.
 *
 * @param handle of the connection
 * @param cfg configurations
 *
 * @return true if success, false otherwise
 */
typedef bool (*connection_config_f)(uint32 handle, attr_container_t *cfg);

/* Raw connection interface for platform to implement */
typedef struct _connection_interface {
    connection_open_f _open;
    connection_close_f _close;
    connection_send_f _send;
    connection_config_f _config;
} connection_interface_t;

/* Platform must define this interface */
extern connection_interface_t connection_impl;

#ifdef __cplusplus
}
#endif

#endif /* CONNECTION_LIB_H_ */
