/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdbool.h>
#include "display_indev.h"
#include "sys/time.h"
#include "SDL2/SDL.h"
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

void
display_vdb_write(void *buf, lv_coord_t buf_w, lv_coord_t x, lv_coord_t y,
                  lv_color_t *color, lv_opa_t opa)
{
    unsigned char *buf_xy = buf + 4 * x + 4 * y * buf_w;
    lv_color_t *temp = (lv_color_t *)buf_xy;
    *temp = *color;
    /*
     if (opa != LV_OPA_COVER) {
     lv_color_t mix_color;

     mix_color.red = *buf_xy;
     mix_color.green = *(buf_xy+1);
     mix_color.blue = *(buf_xy+2);
     color = lv_color_mix(color, mix_color, opa);
     }
     */
}
int
time_get_ms()
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
              const lv_color_t *color_p)
{
    /*Return if the area is out the screen*/
    if (x2 < 0 || y2 < 0 || x1 > MONITOR_HOR_RES - 1
        || y1 > MONITOR_VER_RES - 1) {
        return;
    }

    int32_t y;
    uint32_t w = x2 - x1 + 1;
    for (y = y1; y <= y2; y++) {
        memcpy(&tft_fb[y * MONITOR_HOR_RES + x1], color_p,
               w * sizeof(lv_color_t));

        color_p += w;
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
monitor_fill(int32_t x1, int32_t y1, int32_t x2, int32_t y2, lv_color_t color)
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
    uint32_t color32 = color.full; // lv_color_to32(color);

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
 * @param color_p an array of colors
 */
void
monitor_map(int32_t x1, int32_t y1, int32_t x2, int32_t y2,
            const lv_color_t *color_p)
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
                color_p->full; // lv_color_to32(*color_p);
            color_p++;
        }

        color_p += x2 - act_x2;
    }

    sdl_refr_qry = true;
}

void
display_init(void)
{}

void
display_flush(int32_t x1, int32_t y1, int32_t x2, int32_t y2,
              const lv_color_t *color_p)
{
    monitor_flush(x1, y1, x2, y2, color_p);
}
void
display_fill(int32_t x1, int32_t y1, int32_t x2, int32_t y2, lv_color_t color_p)
{
    monitor_fill(x1, y1, x2, y2, color_p);
}
void
display_map(int32_t x1, int32_t y1, int32_t x2, int32_t y2,
            const lv_color_t *color_p)
{
    monitor_map(x1, y1, x2, y2, color_p);
}

bool
display_input_read(lv_indev_data_t *data)
{
    return mouse_read(data);
}

void
display_deinit(void)
{}

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

void
monitor_sdl_refr_core(void)
{
    if (sdl_refr_qry != false) {
        sdl_refr_qry = false;

        SDL_UpdateTexture(texture, NULL, tft_fb,
                          MONITOR_HOR_RES * sizeof(uint32_t));
        SDL_RenderClear(renderer);
        /*Test: Draw a background to test transparent screens
         * (LV_COLOR_SCREEN_TRANSP)*/
        //        SDL_SetRenderDrawColor(renderer, 0xff, 0, 0, 0xff);
        //        SDL_Rect r;
        //        r.x = 0; r.y = 0; r.w = MONITOR_HOR_RES; r.w =
        //        MONITOR_VER_RES; SDL_RenderDrawRect(renderer, &r);
        /*Update the renderer with the texture containing the rendered image*/
        SDL_RenderCopy(renderer, texture, NULL, NULL);
        SDL_RenderPresent(renderer);
    }

    SDL_Event event;
    while (SDL_PollEvent(&event)) {
#if USE_MOUSE != 0
        mouse_handler(&event);
#endif
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
