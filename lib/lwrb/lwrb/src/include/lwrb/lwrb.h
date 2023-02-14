/**
 * \file            lwrb.h
 * \brief           LwRB - Lightweight ring buffer
 */

/*
 * Copyright (c) 2022 Tilen MAJERLE
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * This file is part of LwRB - Lightweight ring buffer library.
 *
 * Author:          Tilen MAJERLE <tilen@majerle.eu>
 * Version:         v2.0.3
 */
#ifndef LWRB_HDR_H
#define LWRB_HDR_H

#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \defgroup        LWRB Lightweight ring buffer manager
 * \brief           Lightweight ring buffer manager
 * \{
 */

/**
 * \brief           Enable buffer structure pointer parameters as volatile
 * To use this feature, uncomment keyword below, or define in global compiler settings
 */
#ifndef LWRB_VOLATILE
#define LWRB_VOLATILE                           /* volatile */
#endif

/**
 * \brief           Adds 2 magic words to make sure if memory is corrupted
 *                  application can detect wrong data pointer and maximum size
 */
#ifndef LWRB_USE_MAGIC
#define LWRB_USE_MAGIC                          1
#endif

/**
 * \brief           Event type for buffer operations
 */
typedef enum {
    LWRB_EVT_READ,                              /*!< Read event */
    LWRB_EVT_WRITE,                             /*!< Write event */
    LWRB_EVT_RESET,                             /*!< Reset event */
} lwrb_evt_type_t;

/**
 * \brief           Buffer structure forward declaration
 */
struct lwrb;

/**
 * \brief           Event callback function type
 * \param[in]       buff: Buffer handle for event
 * \param[in]       evt: Event type
 * \param[in]       bp: Number of bytes written or read (when used), depends on event type
 */
typedef void (*lwrb_evt_fn)(struct lwrb* buff, lwrb_evt_type_t evt, size_t bp);

/**
 * \brief           Buffer structure
 */
typedef struct lwrb {
#if LWRB_USE_MAGIC
    uint32_t magic1;                            /*!< Magic 1 word */
#endif /* LWRB_USE_MAGIC */
    uint8_t* buff;                              /*!< Pointer to buffer data.
                                                    Buffer is considered initialized when `buff != NULL` and `size > 0` */
    LWRB_VOLATILE size_t size;                  /*!< Size of buffer data. Size of actual buffer is `1` byte less than value holds */
    LWRB_VOLATILE size_t r;                     /*!< Next read pointer. Buffer is considered empty when `r == w` and full when `w == r - 1` */
    LWRB_VOLATILE size_t w;                     /*!< Next write pointer. Buffer is considered empty when `r == w` and full when `w == r - 1` */
    lwrb_evt_fn evt_fn;                         /*!< Pointer to event callback function */
#if LWRB_USE_MAGIC
    uint32_t magic2;                            /*!< Magic 2 word */
#endif /* LWRB_USE_MAGIC */
} lwrb_t;

uint8_t     lwrb_init(lwrb_t* buff, void* buffdata, size_t size);
uint8_t     lwrb_is_ready(lwrb_t* buff);
void        lwrb_free(lwrb_t* buff);
void        lwrb_reset(lwrb_t* buff);
void        lwrb_set_evt_fn(lwrb_t* buff, lwrb_evt_fn fn);

/* Read/Write functions */
size_t      lwrb_write(lwrb_t* buff, const void* data, size_t btw);
size_t      lwrb_read(lwrb_t* buff, void* data, size_t btr);
size_t      lwrb_peek(lwrb_t* buff, size_t skip_count, void* data, size_t btp);

/* Buffer size information */
size_t      lwrb_get_free(lwrb_t* buff);
size_t      lwrb_get_full(lwrb_t* buff);

/* Read data block management */
void*       lwrb_get_linear_block_read_address(lwrb_t* buff);
size_t      lwrb_get_linear_block_read_length(lwrb_t* buff);
size_t      lwrb_skip(lwrb_t* buff, size_t len);

/* Write data block management */
void*       lwrb_get_linear_block_write_address(lwrb_t* buff);
size_t      lwrb_get_linear_block_write_length(lwrb_t* buff);
size_t      lwrb_advance(lwrb_t* buff, size_t len);

/**
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LWRB_HDR_H */
