/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  
 *  am2320: AM2320/2321 I2C Sensor Driver
 *  Copyright (C) 2015 Takeshi HASEGAWA
 *
 * This file is modified version of:
 * https://github.com/takagi/am2321
 *
 * Licensed under the LGPL License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include "in_am2320.h"
#include "am2320.h"

/*
 *  udelay function
 */

long timeval_to_usec(struct timeval tm) {
    return tm.tv_sec * 1000000 + tm.tv_usec;
}

void udelay(long us) {
    struct timeval current;
    struct timeval start;

    gettimeofday(&start, NULL);
    do {
        gettimeofday( &current, NULL);
    } while(timeval_to_usec(current) - timeval_to_usec( start ) < us);
}

/*
 *  CRC16
 */

unsigned short crc16(unsigned char *ptr, unsigned char len) {
    unsigned short crc = 0xFFFF;
    unsigned char i;

    while(len--) {
        crc ^= *ptr++;
        for(i = 0; i < 8; i++) {
            if(crc & 0x01) {
                crc >>= 1;
                crc ^= 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }

    return crc;
}

unsigned char crc16_low(unsigned short crc) {
    return crc & 0xFF;
}

unsigned char crc16_high(unsigned short crc) {
    return crc >> 8;
}

int in_am2320_check_crc16(unsigned char* data) {
    unsigned short crc_m, crc_s;

    crc_m = crc16(data, 6);
    crc_s = (data[7] << 8) + data[6];
    if (crc_m != crc_s) {
        return 0;
    }

    return 1;
}

int in_am2320_read(struct flb_config *config, void *in_context) {
    int retries = 5;

    struct flb_in_am2320_config *ctx = in_context;
    int fd;
    unsigned char data[8];

    fd = open(IN_AM2320_I2C_DEVICE, O_RDWR);
    if (fd < 0) {
        flb_debug("[in_am2320] could not open I2C device: %s",
            IN_AM2320_I2C_DEVICE);
        return 1;
    }

    /* set address of I2C device in 7 bits */
    int ret = ioctl( fd, I2C_SLAVE, IN_AM2320_I2C_ADDRESS);
    if (ret < 0) {
        flb_debug("[in_am2320] could not select I2C address: %x",
            IN_AM2320_I2C_ADDRESS);
        goto error;
    }

    /* write measurement request */
    data[0] = 0x03;
    data[1] = 0x00;
    data[2] = 0x04;

    while (retries) {
        /* wake I2C device up */
        write( fd, NULL, 0);

        ret = write(fd, data, 3);

        if (ret >= 0)
            break;

        flb_debug("[in_am2320] write error, retries = %d");
        udelay(1000);
        retries--;
    }

    if (ret < 0) {
        flb_debug("[in_am2320] write error");
        goto error;
    }

    /* wait for having measured */
    udelay(1500);

    /* read measured result */
    memset(data, 0x00, 8);
    ret = read(fd, data, 8);
    if (ret < 0)
        goto error;

    /* close I2C device */
    close(fd);

    if (! in_am2320_check_crc16(data)) {
      flb_debug("[in_am2320] CRC error");
      return 0;
    }

    double temp = (double) ((data[4] << 8) + data[5]) / 10;
    double humidity = (double) ((data[2] << 8) + data[3]) / 10;

    msgpack_pack_map(&ctx->pckr, 3);
    msgpack_pack_raw(&ctx->pckr, 4);
    msgpack_pack_raw_body(&ctx->pckr, "time", 4);
    msgpack_pack_uint64(&ctx->pckr, time(NULL));
    msgpack_pack_raw(&ctx->pckr, 11);
    msgpack_pack_raw_body(&ctx->pckr, "temperature", 11);
    msgpack_pack_double(&ctx->pckr, temp);
    msgpack_pack_raw(&ctx->pckr, 8);
    msgpack_pack_raw_body(&ctx->pckr, "humidity", 8);
    msgpack_pack_double(&ctx->pckr, humidity);

    flb_debug("[in_am2320] temperature %f humidity %f (buffer=%i)",
        temp, humidity, ctx->idx);
    ctx->idx++;

    return 1;
error:
    /* close I2C device */
    close(fd);

    return 0;
}
