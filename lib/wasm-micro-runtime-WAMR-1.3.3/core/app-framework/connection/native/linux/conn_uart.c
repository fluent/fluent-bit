/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "conn_uart.h"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

static int
parse_baudrate(int baud)
{
    switch (baud) {
        case 9600:
            return B9600;
        case 19200:
            return B19200;
        case 38400:
            return B38400;
        case 57600:
            return B57600;
        case 115200:
            return B115200;
        case 230400:
            return B230400;
        case 460800:
            return B460800;
        case 500000:
            return B500000;
        case 576000:
            return B576000;
        case 921600:
            return B921600;
        case 1000000:
            return B1000000;
        case 1152000:
            return B1152000;
        case 1500000:
            return B1500000;
        case 2000000:
            return B2000000;
        case 2500000:
            return B2500000;
        case 3000000:
            return B3000000;
        case 3500000:
            return B3500000;
        case 4000000:
            return B4000000;
        default:
            return -1;
    }
}

int
uart_open(char *device, int baudrate)
{
    int uart_fd;
    struct termios uart_term;

    uart_fd = open(device, O_RDWR | O_NOCTTY);

    if (uart_fd < 0)
        return -1;

    memset(&uart_term, 0, sizeof(uart_term));
    uart_term.c_cflag = parse_baudrate(baudrate) | CS8 | CLOCAL | CREAD;
    uart_term.c_iflag = IGNPAR;
    uart_term.c_oflag = 0;

    /* set noncanonical mode */
    uart_term.c_lflag = 0;
    uart_term.c_cc[VTIME] = 30;
    uart_term.c_cc[VMIN] = 1;
    tcflush(uart_fd, TCIFLUSH);

    if (tcsetattr(uart_fd, TCSANOW, &uart_term) != 0) {
        close(uart_fd);
        return -1;
    }

    /* Put the fd in non-blocking mode */
    if (fcntl(uart_fd, F_SETFL, fcntl(uart_fd, F_GETFL) | O_NONBLOCK) < 0) {
        close(uart_fd);
        return -1;
    }

    return uart_fd;
}

int
uart_send(int fd, const char *data, int size)
{
    return write(fd, data, size);
}

int
uart_recv(int fd, char *buffer, int buf_size)
{
    return read(fd, buffer, buf_size);
}
