/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>

#include <xbee.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <msgpack.h>

#include "in_xbee.h"
#include "in_xbee_iosampling.h"
#include "in_xbee_config.h"
#include "in_xbee_utils.h"

struct xbee_ioport {
    unsigned int mask;
    const char *port_name;
};

static struct xbee_ioport digital_ports[] = {
    {  1 << 0, "DIO0" },
    {  1 << 1, "DIO1" },
    {  1 << 2, "DIO2" },
    {  1 << 3, "DIO3" },
    {  1 << 4, "DIO4" },
    {  1 << 5, "DIO5" },
    {  1 << 6, "DIO6" },
    {  1 << 7, "GPIO7" },
    {  1 << 10, "DIO10" },
    {  1 << 11, "DIO11" },
    {  1 << 12, "DIO12" },
};

static struct xbee_ioport analog_ports[] = {
    {  1 << 0, "AD0" },
    {  1 << 1, "AD1" },
    {  1 << 2, "AD2" },
    {  1 << 3, "AD3" },
    {  1 << 7, "VCC" },
};

void in_xbee_flush_if_needed(struct flb_in_xbee_config *ctx);

/*
 * returns how many datas in the iosample packet
 */
int in_xbee_iosampling_count_maps(unsigned int mask_din, unsigned int mask_ain)
{
    int i;
    int map_len = 0;
    for (i = 0; i < sizeof(digital_ports) / sizeof(struct xbee_ioport); i++)
        if (mask_din & digital_ports[i].mask)
            map_len++;

    for (i = 0; i < sizeof(analog_ports) / sizeof(struct xbee_ioport); i++)
        if (mask_ain & analog_ports[i].mask)
            map_len++;

    return map_len;
}

int in_xbee_iosampling_decode_ios(struct msgpack_packer *buf, unsigned char *p, unsigned int mask_din, unsigned int mask_ain)
{
    int i;
    int din;

    /*
     * Digital pins data comes first.
     */
    if (mask_din) {
        /* sampled digital data sets */
        din = *p << 8 | *(p + 1);
        p += 2;

    for (i = 0; i < sizeof(digital_ports) / sizeof(struct xbee_ioport); i++) {
            struct xbee_ioport *port = &digital_ports[i];
            if (mask_din & port->mask) {
                msgpack_pack_bin(buf, strlen(port->port_name));
                msgpack_pack_bin_body(buf, (char*) port->port_name, strlen(port->port_name));
                msgpack_pack_int(buf, (din & port->mask) > 0);
            }
        }
    }

    /*
     * Analog pins 
     */
    for (i = 0; i < sizeof(analog_ports) / sizeof(struct xbee_ioport); i++) {
        struct xbee_ioport *port = &analog_ports[i];
            if (mask_ain & port->mask) {
                msgpack_pack_bin(buf, strlen(port->port_name));
                msgpack_pack_bin_body(buf, (char*) port->port_name, strlen(port->port_name));
		msgpack_pack_int(buf, *p << 8 | *(p + 1));
		p += 2;
        }
    }

   /*
    * FixMe: num of maps should match with in_xbee_iosample_count_maps() result
    */
   return 1;
}

void in_xbee_iosampling_cb(struct xbee *xbee, struct xbee_con *con,
                struct xbee_pkt **pkt, void **data)
{
    struct flb_in_xbee_config *ctx = *data;
    int map_len = 0;
    unsigned int mask_din, mask_ain;
    char source_addr[8 * 2 + 1];

    if ((*pkt)->dataLen == 0) {
        flb_debug("xbee data length too short, skip");
        return;
    }

    unsigned char *p = (unsigned char*) (*pkt)->data;

    if (*p != 1)
        return;

    mask_din = *(p + 1) << 8 | *(p + 2);
    mask_ain = *(p + 3);

    map_len = in_xbee_iosampling_count_maps(mask_din, mask_ain);
    map_len++; /* for addr field */

    p += 4;

    in_xbee_conAddress2str((char*) &source_addr, sizeof(source_addr), &(*pkt)->address);

    flb_debug("[xbee] IO sample: mask_din=0x%x mask_ain=%x map_len=%d", mask_din, mask_ain, map_len);

    pthread_mutex_lock(&ctx->mtx_mp);

    in_xbee_flush_if_needed(ctx);
    ctx->buffer_id++;

    msgpack_pack_array(&ctx->mp_pck, 2);
    msgpack_pack_uint64(&ctx->mp_pck, time(NULL));
    msgpack_pack_map(&ctx->mp_pck, map_len);

    /* source address */
    msgpack_pack_bin(&ctx->mp_pck, 8);
    msgpack_pack_bin_body(&ctx->mp_pck, "src_addr", 8);
    msgpack_pack_bin(&ctx->mp_pck, strlen((char*) &source_addr));
    msgpack_pack_bin_body(&ctx->mp_pck, (char*) &source_addr, strlen((char*) &source_addr));

    in_xbee_iosampling_decode_ios(&ctx->mp_pck, p, mask_din, mask_ain);

    pthread_mutex_unlock(&ctx->mtx_mp);
}
