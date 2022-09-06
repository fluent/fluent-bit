/**
 * @file XPT2046.h
 *
 */

#ifndef XPT2046_H
#define XPT2046_H

#define USE_XPT2046 1

#define XPT2046_HOR_RES 320
#define XPT2046_VER_RES 240
#define XPT2046_X_MIN 200
#define XPT2046_Y_MIN 200
#define XPT2046_X_MAX 3800
#define XPT2046_Y_MAX 3800
#define XPT2046_AVG 4
#define XPT2046_INV 0

#define CMD_X_READ 0b10010000
#define CMD_Y_READ 0b11010000

#ifdef __cplusplus
extern "C" {
#endif

/*********************
 *      INCLUDES
 *********************/

#if USE_XPT2046
#include <autoconf.h>
#include <stdint.h>
#include <stdbool.h>
#include "lv_hal/lv_hal_indev.h"
#include "device.h"
#include "drivers/gpio.h"

/*********************
 *      DEFINES
 *********************/

/**********************
 *      TYPEDEFS
 **********************/

/**********************
 * GLOBAL PROTOTYPES
 **********************/
void
xpt2046_init(void);
bool
xpt2046_read(lv_indev_data_t *data);

/**********************
 *      MACROS
 **********************/

#endif /* USE_XPT2046 */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* XPT2046_H */
