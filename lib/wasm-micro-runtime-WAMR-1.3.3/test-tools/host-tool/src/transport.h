/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef DEPS_APP_MGR_HOST_TOOL_SRC_TRANSPORT_H_
#define DEPS_APP_MGR_HOST_TOOL_SRC_TRANSPORT_H_

#ifdef __cplusplus
extern "C" {
#endif

/* IMRT link message between host and WAMR */
typedef struct {
    unsigned short message_type;
    unsigned int payload_size;
    char *payload;
} imrt_link_message_t;

/* The receive phase of IMRT link message */
typedef enum {
    Phase_Non_Start,
    Phase_Leading,
    Phase_Type,
    Phase_Size,
    Phase_Payload
} recv_phase_t;

/* The receive context of IMRT link message */
typedef struct {
    recv_phase_t phase;
    int size_in_phase;
    imrt_link_message_t message;
} imrt_link_recv_context_t;

/**
 * @brief Send data to WAMR.
 *
 * @param fd the connection fd to WAMR
 * @param buf the buffer that contains content to be sent
 * @param len size of the buffer to be sent
 *
 * @return true if success, false if fail
 */
bool
host_tool_send_data(int fd, const char *buf, unsigned int len);

/**
 * @brief Handle one byte of IMRT link message
 *
 * @param ch the one byte from WAMR to be handled
 * @param ctx the receive context
 *
 * @return -1 invalid sync byte
 *          1 byte added to buffer, waiting more for complete packet
 *          0 completed packet
 *          2 in receiving payload
 */
int
on_imrt_link_byte_arrive(unsigned char ch, imrt_link_recv_context_t *ctx);

/**
 * @brief Initialize TCP connection with remote server.
 *
 * @param address the network address of peer
 * @param port the network port of peer
 * @param fd pointer of integer to save the socket fd once return success
 *
 * @return true if success, false if fail
 */
bool
tcp_init(const char *address, uint16_t port, int *fd);

/**
 * @brief Initialize UART connection with remote.
 *
 * @param device name of the UART device
 * @param baudrate baudrate of the device
 * @param fd pointer of integer to save the uart fd once return success
 *
 * @return true if success, false if fail
 */
bool
uart_init(const char *device, int baudrate, int *fd);

/**
 * @brief Parse UART baudrate from an integer
 *
 * @param the baudrate interger to be parsed
 *
 * @return true if success, false if fail
 *
 * @par
 * @code
 * int baudrate = parse_baudrate(9600);
 * ...
 * uart_term.c_cflag = baudrate;
 * ...
 * @endcode
 */
int
parse_baudrate(int baud);

/**
 * @brief Send data over UDP.
 *
 * @param address network address of the remote
 * @param port network port of the remote
 * @param buf the buffer that contains content to be sent
 * @param len size of the buffer to be sent
 *
 * @return true if success, false if fail
 */
bool
udp_send(const char *address, int port, const char *buf, int len);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* DEPS_APP_MGR_HOST_TOOL_SRC_TRANSPORT_H_ */
