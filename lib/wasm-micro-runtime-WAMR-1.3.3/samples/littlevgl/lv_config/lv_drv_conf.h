/**
 * @file lv_drv_conf.h
 *
 */

/*
 * COPY THIS FILE AS lv_drv_conf.h
 */

#if 1 /*Set it to "1" to enable the content*/

#ifndef LV_DRV_CONF_H
#define LV_DRV_CONF_H

#include "lv_conf.h"

/*********************
 * DELAY INTERFACE
 *********************/
#define LV_DRV_DELAY_INCLUDE  <stdint.h>            /*Dummy include by default*/
#define LV_DRV_DELAY_US(us)  /*delay_us(us)*/       /*Delay the given number of microseconds*/
#define LV_DRV_DELAY_MS(ms)  /*delay_ms(ms)*/       /*Delay the given number of milliseconds*/

/*********************
 * DISPLAY INTERFACE
 *********************/

/*------------
 *  Common
 *------------*/
#define LV_DRV_DISP_INCLUDE         <stdint.h>           /*Dummy include by default*/
#define LV_DRV_DISP_CMD_DATA(val)  /*pin_x_set(val)*/    /*Set the command/data pin to 'val'*/
#define LV_DRV_DISP_RST(val)       /*pin_x_set(val)*/    /*Set the reset pin to 'val'*/

/*---------
 *  SPI
 *---------*/
#define LV_DRV_DISP_SPI_CS(val)          /*spi_cs_set(val)*/     /*Set the SPI's Chip select to 'val'*/
#define LV_DRV_DISP_SPI_WR_BYTE(data)    /*spi_wr(data)*/        /*Write a byte the SPI bus*/
#define LV_DRV_DISP_SPI_WR_ARRAY(adr, n) /*spi_wr_mem(adr, n)*/  /*Write 'n' bytes to SPI bus from 'adr'*/

/*------------------
 *  Parallel port
 *-----------------*/
#define LV_DRV_DISP_PAR_CS(val)          /*par_cs_set(val)*/   /*Set the Parallel port's Chip select to 'val'*/
#define LV_DRV_DISP_PAR_SLOW             /*par_slow()*/        /*Set low speed on the parallel port*/
#define LV_DRV_DISP_PAR_FAST             /*par_fast()*/        /*Set high speed on the parallel port*/
#define LV_DRV_DISP_PAR_WR_WORD(data)    /*par_wr(data)*/      /*Write a word to the parallel port*/
#define LV_DRV_DISP_PAR_WR_ARRAY(adr, n) /*par_wr_mem(adr,n)*/ /*Write 'n' bytes to Parallel ports from 'adr'*/

/***************************
 * INPUT DEVICE INTERFACE
 ***************************/

/*----------
 *  Common
 *----------*/
#define LV_DRV_INDEV_INCLUDE     <stdint.h>             /*Dummy include by default*/
#define LV_DRV_INDEV_RST(val)    /*pin_x_set(val)*/     /*Set the reset pin to 'val'*/
#define LV_DRV_INDEV_IRQ_READ    0 /*pn_x_read()*/      /*Read the IRQ pin*/

/*---------
 *  SPI
 *---------*/
#define LV_DRV_INDEV_SPI_CS(val)            /*spi_cs_set(val)*/     /*Set the SPI's Chip select to 'val'*/
#define LV_DRV_INDEV_SPI_XCHG_BYTE(data)    0 /*spi_xchg(val)*/     /*Write 'val' to SPI and give the read value*/

/*---------
 *  I2C
 *---------*/
#define LV_DRV_INDEV_I2C_START              /*i2c_start()*/       /*Make an I2C start*/
#define LV_DRV_INDEV_I2C_STOP               /*i2c_stop()*/        /*Make an I2C stop*/
#define LV_DRV_INDEV_I2C_RESTART            /*i2c_restart()*/     /*Make an I2C restart*/
#define LV_DRV_INDEV_I2C_WR(data)           /*i2c_wr(data)*/      /*Write a byte to the I1C bus*/
#define LV_DRV_INDEV_I2C_READ(last_read)    0 /*i2c_rd()*/        /*Read a byte from the I2C bud*/


/*********************
 *  DISPLAY DRIVERS
 *********************/

/*-------------------
 *  Monitor of PC
 *-------------------*/
#ifndef USE_MONITOR
#  define USE_MONITOR         1
#endif

#if USE_MONITOR
#  define MONITOR_HOR_RES     LV_HOR_RES_MAX
#  define MONITOR_VER_RES     LV_VER_RES_MAX

/* Scale window by this factor (useful when simulating small screens) */
#  define MONITOR_ZOOM        1

/* Used to test true double buffering with only address changing.
 * Set LV_VDB_SIZE = (LV_HOR_RES * LV_VER_RES) and  LV_VDB_DOUBLE = 1 and LV_COLOR_DEPTH = 32" */
#  define MONITOR_DOUBLE_BUFFERED 0

/*Eclipse: <SDL2/SDL.h>    Visual Studio: <SDL.h>*/
#  define MONITOR_SDL_INCLUDE_PATH    <SDL2/SDL.h>

/*Different rendering might be used if running in a Virtual machine*/
#  define MONITOR_VIRTUAL_MACHINE 0

/*Open two windows to test multi display support*/
#  define MONITOR_DUAL            0
#endif

/*-----------------------------------
 *  Native Windows (including mouse)
 *----------------------------------*/
#ifndef USE_WINDOWS
#  define USE_WINDOWS       0
#endif

#define USE_WINDOWS         0
#if USE_WINDOWS
#  define WINDOW_HOR_RES      480
#  define WINDOW_VER_RES      320
#endif

/*----------------
 *    SSD1963
 *--------------*/
#ifndef USE_SSD1963
#  define USE_SSD1963         0
#endif

#if USE_SSD1963
#  define SSD1963_HOR_RES     LV_HOR_RES
#  define SSD1963_VER_RES     LV_VER_RES
#  define SSD1963_HT          531
#  define SSD1963_HPS         43
#  define SSD1963_LPS         8
#  define SSD1963_HPW         10
#  define SSD1963_VT          288
#  define SSD1963_VPS         12
#  define SSD1963_FPS         4
#  define SSD1963_VPW         10
#  define SSD1963_HS_NEG      0   /*Negative hsync*/
#  define SSD1963_VS_NEG      0   /*Negative vsync*/
#  define SSD1963_ORI         0   /*0, 90, 180, 270*/
#  define SSD1963_COLOR_DEPTH 16
#endif

/*----------------
 *    R61581
 *--------------*/
#ifndef USE_R61581
#  define USE_R61581          0
#endif

#if USE_R61581
#  define R61581_HOR_RES      LV_HOR_RES
#  define R61581_VER_RES      LV_VER_RES
#  define R61581_HSPL         0       /*HSYNC signal polarity*/
#  define R61581_HSL          10      /*HSYNC length (Not Implemented)*/
#  define R61581_HFP          10      /*Horitontal Front poarch (Not Implemented)*/
#  define R61581_HBP          10      /*Horitontal Back poarch (Not Implemented */
#  define R61581_VSPL         0       /*VSYNC signal polarity*/
#  define R61581_VSL          10      /*VSYNC length (Not Implemented)*/
#  define R61581_VFP          8       /*Vertical Front poarch*/
#  define R61581_VBP          8       /*Vertical Back poarch */
#  define R61581_DPL          0       /*DCLK signal polarity*/
#  define R61581_EPL          1       /*ENABLE signal polarity*/
#  define R61581_ORI          0       /*0, 180*/
#  define R61581_LV_COLOR_DEPTH 16    /*Fix 16 bit*/
#endif

/*------------------------------
 *  ST7565 (Monochrome, low res.)
 *-----------------------------*/
#ifndef USE_ST7565
#  define USE_ST7565          0
#endif

#if USE_ST7565
/*No settings*/
#endif  /*USE_ST7565*/

/*-----------------------------------------
 *  Linux frame buffer device (/dev/fbx)
 *-----------------------------------------*/
#ifndef USE_FBDEV
#  define USE_FBDEV           1
#endif

#if USE_FBDEV
#  define FBDEV_PATH          "/dev/fb0"
#endif

/*********************
 *  INPUT DEVICES
 *********************/

/*--------------
 *    XPT2046
 *--------------*/
#ifndef USE_XPT2046
#  define USE_XPT2046         0
#endif

#if USE_XPT2046
#  define XPT2046_HOR_RES     480
#  define XPT2046_VER_RES     320
#  define XPT2046_X_MIN       200
#  define XPT2046_Y_MIN       200
#  define XPT2046_X_MAX       3800
#  define XPT2046_Y_MAX       3800
#  define XPT2046_AVG         4
#  define XPT2046_INV         0
#endif

/*-----------------
 *    FT5406EE8
 *-----------------*/
#ifndef USE_FT5406EE8
#  define USE_FT5406EE8       0
#endif

#if USE_FT5406EE8
# define FT5406EE8_I2C_ADR   0x38                  /*7 bit address*/
#endif

/*---------------
 *  AD TOUCH
 *--------------*/
#ifndef USE_AD_TOUCH
#  define USE_AD_TOUCH        0
#endif

#if USE_AD_TOUCH
/*No settings*/
#endif


/*---------------------------------------
 * Mouse or touchpad on PC (using SDL)
 *-------------------------------------*/
#ifndef USE_MOUSE
#  define USE_MOUSE           1
#endif

#if USE_MOUSE
/*No settings*/
#endif

/*-------------------------------------------
 * Mousewheel as encoder on PC (using SDL)
 *------------------------------------------*/
#ifndef USE_MOUSEWHEEL
#  define USE_MOUSEWHEEL      1
#endif

#if USE_MOUSEWHEEL
/*No settings*/
#endif

/*-------------------------------------------------
 * Touchscreen as libinput interface (for Linux based systems)
 *------------------------------------------------*/
#ifndef USE_LIBINPUT
#  define USE_LIBINPUT           0
#endif

#if USE_LIBINPUT
#  define LIBINPUT_NAME   "/dev/input/event0"        /*You can use the "evtest" Linux tool to get the list of devices and test them*/
#endif  /*USE_LIBINPUT*/

/*-------------------------------------------------
 * Mouse or touchpad as evdev interface (for Linux based systems)
 *------------------------------------------------*/
#ifndef USE_EVDEV
#  define USE_EVDEV           0
#endif

#if USE_EVDEV
#  define EVDEV_NAME   "/dev/input/event0"        /*You can use the "evtest" Linux tool to get the list of devices and test them*/
#  define EVDEV_SWAP_AXES         0               /*Swap the x and y axes of the touchscreen*/

#  define EVDEV_SCALE             0               /* Scale input, e.g. if touchscreen resolution does not match display resolution */
#  if EVDEV_SCALE
#    define EVDEV_SCALE_HOR_RES     (4096)          /* Horizontal resolution of touchscreen */
#    define EVDEV_SCALE_VER_RES     (4096)          /* Vertical resolution of touchscreen */
#  endif  /*EVDEV_SCALE*/

#  define EVDEV_CALIBRATE         0               /*Scale and offset the touchscreen coordinates by using maximum and minimum values for each axis*/
#  if EVDEV_CALIBRATE
#    define EVDEV_HOR_MIN   3800                    /*If EVDEV_XXX_MIN > EVDEV_XXX_MAX the XXX axis is automatically inverted*/
#    define EVDEV_HOR_MAX   200
#    define EVDEV_VER_MIN   200
#    define EVDEV_VER_MAX   3800
#  endif  /*EVDEV_SCALE*/
#endif  /*USE_EVDEV*/

/*-------------------------------
 *   Keyboard of a PC (using SDL)
 *------------------------------*/
#ifndef USE_KEYBOARD
#  define USE_KEYBOARD        1
#endif

#if USE_KEYBOARD
/*No settings*/
#endif

#endif  /*LV_DRV_CONF_H*/

#endif /*End of "Content enable"*/
