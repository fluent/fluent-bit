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

/* I2C character device */
#define IN_AM2320_I2C_DEVICE "/dev/i2c-1"
#define IN_AM2320_I2C_ADDRESS (0xB8 >> 1)

/* I2C device access */
int in_am2320_read(struct flb_config *config, void *in_context);
