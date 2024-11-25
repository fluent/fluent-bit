/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdbool.h>
#include "display_indev.h"
#include "SDL2/SDL.h"
#include "sys/time.h"
#include "wasm_export.h"
#include "app_manager_export.h"

#define MONITOR_HOR_RES 320
#define MONITOR_VER_RES 240
#ifndef MONITOR_ZOOM
#define MONITOR_ZOOM 1
#endif
#define SDL_REFR_PERIOD 50
void
monitor_sdl_init(void);
void
monitor_sdl_refr_core(void);
void
monitor_sdl_clean_up(void);

static uint32_t tft_fb[MONITOR_HOR_RES * MONITOR_VER_RES];

int
time_get_ms(wasm_exec_env_t exec_env)
{
    static struct timeval tv;
    gettimeofday(&tv, NULL);
    long long time_in_mill = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000;

    return (int)time_in_mill;
}

SDL_Window *window;
SDL_Renderer *renderer;
SDL_Texture *texture;
static volatile bool sdl_inited = false;
static volatile bool sdl_refr_qry = false;
static volatile bool sdl_quit_qry = false;

void
monitor_flush(int32_t x1, int32_t y1, int32_t x2, int32_t y2,
              const lv_color_t *color)
{
    /*Return if the area is out the screen*/
    if (x2 < 0 || y2 < 0 || x1 > MONITOR_HOR_RES - 1
        || y1 > MONITOR_VER_RES - 1) {
        return;
    }

    int32_t y;
    uint32_t w = x2 - x1 + 1;

    for (y = y1; y <= y2; y++) {
        memcpy(&tft_fb[y * MONITOR_HOR_RES + x1], color,
               w * sizeof(lv_color_t));

        color += w;
    }
    sdl_refr_qry = true;

    /*IMPORTANT! It must be called to tell the system the flush is ready*/
}

/**
 * Fill out the marked area with a color
 * @param x1 left coordinate
 * @param y1 top coordinate
 * @param x2 right coordinate
 * @param y2 bottom coordinate
 * @param color fill color
 */
void
monitor_fill(int32_t x1, int32_t y1, int32_t x2, int32_t y2, lv_color_t *color)
{
    /*Return if the area is out the screen*/
    if (x2 < 0)
        return;
    if (y2 < 0)
        return;
    if (x1 > MONITOR_HOR_RES - 1)
        return;
    if (y1 > MONITOR_VER_RES - 1)
        return;

    /*Truncate the area to the screen*/
    int32_t act_x1 = x1 < 0 ? 0 : x1;
    int32_t act_y1 = y1 < 0 ? 0 : y1;
    int32_t act_x2 = x2 > MONITOR_HOR_RES - 1 ? MONITOR_HOR_RES - 1 : x2;
    int32_t act_y2 = y2 > MONITOR_VER_RES - 1 ? MONITOR_VER_RES - 1 : y2;

    int32_t x;
    int32_t y;
    uint32_t color32 = color->full; // lv_color_to32(color);

    for (x = act_x1; x <= act_x2; x++) {
        for (y = act_y1; y <= act_y2; y++) {
            tft_fb[y * MONITOR_HOR_RES + x] = color32;
        }
    }

    sdl_refr_qry = true;
}

/**
 * Put a color map to the marked area
 * @param x1 left coordinate
 * @param y1 top coordinate
 * @param x2 right coordinate
 * @param y2 bottom coordinate
 * @param color an array of colors
 */
void
monitor_map(int32_t x1, int32_t y1, int32_t x2, int32_t y2,
            const lv_color_t *color)
{
    /*Return if the area is out the screen*/
    if (x2 < 0)
        return;
    if (y2 < 0)
        return;
    if (x1 > MONITOR_HOR_RES - 1)
        return;
    if (y1 > MONITOR_VER_RES - 1)
        return;

    /*Truncate the area to the screen*/
    int32_t act_x1 = x1 < 0 ? 0 : x1;
    int32_t act_y1 = y1 < 0 ? 0 : y1;
    int32_t act_x2 = x2 > MONITOR_HOR_RES - 1 ? MONITOR_HOR_RES - 1 : x2;
    int32_t act_y2 = y2 > MONITOR_VER_RES - 1 ? MONITOR_VER_RES - 1 : y2;

    int32_t x;
    int32_t y;

    for (y = act_y1; y <= act_y2; y++) {
        for (x = act_x1; x <= act_x2; x++) {
            tft_fb[y * MONITOR_HOR_RES + x] =
                color->full; // lv_color_to32(*color);
            color++;
        }

        color += x2 - act_x2;
    }

    sdl_refr_qry = true;
}

void
display_init(void)
{}

void
display_flush(wasm_exec_env_t exec_env, int32_t x1, int32_t y1, int32_t x2,
              int32_t y2, lv_color_t *color)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);

    if (!wasm_runtime_validate_native_addr(module_inst, color,
                                           sizeof(lv_color_t)))
        return;

    monitor_flush(x1, y1, x2, y2, color);
}

void
display_fill(wasm_exec_env_t exec_env, int32_t x1, int32_t y1, int32_t x2,
             int32_t y2, lv_color_t *color)
{
    monitor_fill(x1, y1, x2, y2, color);
}

void
display_map(wasm_exec_env_t exec_env, int32_t x1, int32_t y1, int32_t x2,
            int32_t y2, const lv_color_t *color)
{
    monitor_map(x1, y1, x2, y2, color);
}

typedef struct display_input_data {
    lv_point_t point;
    uint32 user_data_offset;
    uint8 state;
} display_input_data;

bool
display_input_read(wasm_exec_env_t exec_env, void *input_data_app)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    display_input_data *data_app = (display_input_data *)input_data_app;
    bool ret;

    if (!wasm_runtime_validate_native_addr(module_inst, data_app,
                                           sizeof(display_input_data)))
        return false;

    lv_indev_data_t data = { 0 };

    ret = mouse_read(&data);

    data_app->point = data.point;
    data_app->user_data_offset =
        wasm_runtime_addr_native_to_app(module_inst, data.user_data);
    data_app->state = data.state;

    return ret;
}

void
display_deinit(wasm_exec_env_t exec_env)
{}

void
display_vdb_write(wasm_exec_env_t exec_env, void *buf, lv_coord_t buf_w,
                  lv_coord_t x, lv_coord_t y, lv_color_t *color, lv_opa_t opa)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    unsigned char *buf_xy = (unsigned char *)buf + 4 * x + 4 * y * buf_w;

    if (!wasm_runtime_validate_native_addr(module_inst, color,
                                           sizeof(lv_color_t)))
        return;

    *(lv_color_t *)buf_xy = *color;
}

int
monitor_sdl_refr_thread(void *param)
{
    (void)param;

    /*If not OSX initialize SDL in the Thread*/
    monitor_sdl_init();
    /*Run until quit event not arrives*/
    while (sdl_quit_qry == false) {
        /*Refresh handling*/
        monitor_sdl_refr_core();
    }

    monitor_sdl_clean_up();
    exit(0);

    return 0;
}
extern void
mouse_handler(SDL_Event *event);
void
monitor_sdl_refr_core(void)
{
    if (sdl_refr_qry != false) {
        sdl_refr_qry = false;

        SDL_UpdateTexture(texture, NULL, tft_fb,
                          MONITOR_HOR_RES * sizeof(uint32_t));
        SDL_RenderClear(renderer);
        /*Update the renderer with the texture containing the rendered image*/
        SDL_RenderCopy(renderer, texture, NULL, NULL);
        SDL_RenderPresent(renderer);
    }

    SDL_Event event;
    while (SDL_PollEvent(&event)) {

        mouse_handler(&event);

        if ((&event)->type == SDL_WINDOWEVENT) {
            switch ((&event)->window.event) {
#if SDL_VERSION_ATLEAST(2, 0, 5)
                case SDL_WINDOWEVENT_TAKE_FOCUS:
#endif
                case SDL_WINDOWEVENT_EXPOSED:

                    SDL_UpdateTexture(texture, NULL, tft_fb,
                                      MONITOR_HOR_RES * sizeof(uint32_t));
                    SDL_RenderClear(renderer);
                    SDL_RenderCopy(renderer, texture, NULL, NULL);
                    SDL_RenderPresent(renderer);
                    break;
                default:
                    break;
            }
        }
    }

    /*Sleep some time*/
    SDL_Delay(SDL_REFR_PERIOD);
}
int
quit_filter(void *userdata, SDL_Event *event)
{
    (void)userdata;

    if (event->type == SDL_QUIT) {
        sdl_quit_qry = true;
    }

    return 1;
}

void
monitor_sdl_clean_up(void)
{
    SDL_DestroyTexture(texture);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
}

void
monitor_sdl_init(void)
{
    /*Initialize the SDL*/
    SDL_Init(SDL_INIT_VIDEO);

    SDL_SetEventFilter(quit_filter, NULL);

    window = SDL_CreateWindow(
        "TFT Simulator", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
        MONITOR_HOR_RES * MONITOR_ZOOM, MONITOR_VER_RES * MONITOR_ZOOM,
        0); /*last param. SDL_WINDOW_BORDERLESS to hide borders*/

    renderer = SDL_CreateRenderer(window, -1, 0);
    texture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_ARGB8888,
                                SDL_TEXTUREACCESS_STATIC, MONITOR_HOR_RES,
                                MONITOR_VER_RES);
    SDL_SetTextureBlendMode(texture, SDL_BLENDMODE_BLEND);

    /*Initialize the frame buffer to gray (77 is an empirical value) */
    memset(tft_fb, 0x44, MONITOR_HOR_RES * MONITOR_VER_RES * sizeof(uint32_t));
    SDL_UpdateTexture(texture, NULL, tft_fb,
                      MONITOR_HOR_RES * sizeof(uint32_t));
    sdl_refr_qry = true;
    sdl_inited = true;
}

void
display_SDL_init()
{
    SDL_CreateThread(monitor_sdl_refr_thread, "sdl_refr", NULL);
    while (sdl_inited == false)
        ; /*Wait until 'sdl_refr' initializes the SDL*/
}
