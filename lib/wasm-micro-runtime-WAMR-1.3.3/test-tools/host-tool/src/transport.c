/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <termios.h>
#include <fcntl.h>

#include "transport.h"

#define SA struct sockaddr

unsigned char leading[2] = { 0x12, 0x34 };

bool
tcp_init(const char *address, uint16_t port, int *fd)
{
    int sock;
    struct sockaddr_in servaddr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return false;

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(address);
    servaddr.sin_port = htons(port);

    if (connect(sock, (SA *)&servaddr, sizeof(servaddr)) != 0) {
        close(sock);
        return false;
    }

    *fd = sock;
    return true;
}

int
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

bool
uart_init(const char *device, int baudrate, int *fd)
{
    int uart_fd;
    struct termios uart_term;

    uart_fd = open(device, O_RDWR | O_NOCTTY);

    if (uart_fd < 0)
        return false;

    memset(&uart_term, 0, sizeof(uart_term));
    uart_term.c_cflag = baudrate | CS8 | CLOCAL | CREAD;
    uart_term.c_iflag = IGNPAR;
    uart_term.c_oflag = 0;

    /* set noncanonical mode */
    uart_term.c_lflag = 0;
    uart_term.c_cc[VTIME] = 30;
    uart_term.c_cc[VMIN] = 1;
    tcflush(uart_fd, TCIFLUSH);

    if (tcsetattr(uart_fd, TCSANOW, &uart_term) != 0) {
        close(uart_fd);
        return false;
    }

    *fd = uart_fd;
    return true;
}

bool
udp_send(const char *address, int port, const char *buf, int len)
{
    int sockfd;
    ssize_t size_sent;
    struct sockaddr_in servaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return false;

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    size_sent = sendto(sockfd, buf, len, MSG_CONFIRM,
                       (const struct sockaddr *)&servaddr, sizeof(servaddr));

    close(sockfd);
    return (size_sent != -1) ? true : false;
}

bool
host_tool_send_data(int fd, const char *buf, unsigned int len)
{
    int cnt = 0;
    ssize_t ret;

    if (fd == -1 || buf == NULL || len <= 0) {
        return false;
    }

resend:
    ret = write(fd, buf, len);

    if (ret == -1) {
        if (errno == ECONNRESET) {
            close(fd);
        }

        // repeat sending if the outbuffer is full
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (++cnt > 10) {
                close(fd);
                return false;
            }
            sleep(1);
            goto resend;
        }
    }

    return (ret == len);
}

#define SET_RECV_PHASE(ctx, new_phase) \
    do {                               \
        ctx->phase = new_phase;        \
        ctx->size_in_phase = 0;        \
    } while (0)

/*
 * input:    1 byte from remote
 * output:   parse result
 * return:   -1 invalid sync byte
 *           1 byte added to buffer, waiting more for complete packet
 *           0 completed packet
 *           2 in receiving payload
 */
int
on_imrt_link_byte_arrive(unsigned char ch, imrt_link_recv_context_t *ctx)
{
    if (ctx->phase == Phase_Non_Start) {
        if (ctx->message.payload) {
            free(ctx->message.payload);
            ctx->message.payload = NULL;
            ctx->message.payload_size = 0;
        }

        if (leading[0] == ch) {
            ctx->phase = Phase_Leading;
        }
        else {
            return -1;
        }
    }
    else if (ctx->phase == Phase_Leading) {
        if (leading[1] == ch) {
            SET_RECV_PHASE(ctx, Phase_Type);
        }
        else {
            ctx->phase = Phase_Non_Start;
            return -1;
        }
    }
    else if (ctx->phase == Phase_Type) {
        unsigned char *p = (unsigned char *)&ctx->message.message_type;
        p[ctx->size_in_phase++] = ch;

        if (ctx->size_in_phase == sizeof(ctx->message.message_type)) {
            ctx->message.message_type = ntohs(ctx->message.message_type);
            SET_RECV_PHASE(ctx, Phase_Size);
        }
    }
    else if (ctx->phase == Phase_Size) {
        unsigned char *p = (unsigned char *)&ctx->message.payload_size;
        p[ctx->size_in_phase++] = ch;

        if (ctx->size_in_phase == sizeof(ctx->message.payload_size)) {
            ctx->message.payload_size = ntohl(ctx->message.payload_size);
            SET_RECV_PHASE(ctx, Phase_Payload);

            if (ctx->message.payload) {
                free(ctx->message.payload);
                ctx->message.payload = NULL;
            }

            /* no payload */
            if (ctx->message.payload_size == 0) {
                SET_RECV_PHASE(ctx, Phase_Non_Start);
                return 0;
            }

            ctx->message.payload = (char *)malloc(ctx->message.payload_size);
            SET_RECV_PHASE(ctx, Phase_Payload);
        }
    }
    else if (ctx->phase == Phase_Payload) {
        ctx->message.payload[ctx->size_in_phase++] = ch;

        if (ctx->size_in_phase == ctx->message.payload_size) {
            SET_RECV_PHASE(ctx, Phase_Non_Start);
            return 0;
        }

        return 2;
    }

    return 1;
}
