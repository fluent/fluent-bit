/*
 * Copyright (c) 2017 Jan Van Winkel <jan.van_winkel@dxplore.eu>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "display_ili9340.h"
#include <display.h>

//#define LOG_LEVEL CONFIG_DISPLAY_LOG_LEVEL
//#include <logging/log.h>
// LOG_MODULE_REGISTER(display_ili9340);
#define LOG_ERR printf
#define LOG_DBG printf
#define LOG_WRN printf

#include <drivers/gpio.h>
#include <sys/byteorder.h>
#include <drivers/spi.h>
#include <string.h>
#include <stdio.h>

struct ili9340_data {
    struct device *reset_gpio;
    struct device *command_data_gpio;
    struct device *spi_dev;
    struct spi_config spi_config;
#ifdef DT_ILITEK_ILI9340_0_CS_GPIO_CONTROLLER
    struct spi_cs_control cs_ctrl;
#endif
};

struct ili9340_data ili9340_data1;

#define ILI9340_CMD_DATA_PIN_COMMAND 0
#define ILI9340_CMD_DATA_PIN_DATA 1

static void
ili9340_exit_sleep(struct ili9340_data *data)
{
    ili9340_transmit(data, ILI9340_CMD_EXIT_SLEEP, NULL, 0);
    // k_sleep(Z_TIMEOUT_MS(120));
}

int
ili9340_init()
{
    struct ili9340_data *data = &ili9340_data1;
    printf("Initializing display driver\n");
    data->spi_dev = device_get_binding(DT_ILITEK_ILI9340_0_BUS_NAME);
    if (data->spi_dev == NULL) {
        return -EPERM;
    }
    data->spi_config.frequency = DT_ILITEK_ILI9340_0_SPI_MAX_FREQUENCY;
    data->spi_config.operation =
        SPI_OP_MODE_MASTER
        | SPI_WORD_SET(8); // SPI_OP_MODE_MASTER | SPI_WORD_SET(8);
    data->spi_config.slave = DT_ILITEK_ILI9340_0_BASE_ADDRESS;

#ifdef DT_ILITEK_ILI9340_0_CS_GPIO_CONTROLLER
    data->cs_ctrl.gpio_dev =
        device_get_binding(DT_ILITEK_ILI9340_0_CS_GPIO_CONTROLLER);
    data->cs_ctrl.gpio_pin = DT_ILITEK_ILI9340_0_CS_GPIO_PIN;
    data->cs_ctrl.delay = 0;
    data->spi_config.cs = &(data->cs_ctrl);
#else
    data->spi_config.cs = NULL;
#endif
    data->reset_gpio =
        device_get_binding(DT_ILITEK_ILI9340_0_RESET_GPIOS_CONTROLLER);
    if (data->reset_gpio == NULL) {
        return -EPERM;
    }

    gpio_pin_configure(data->reset_gpio, DT_ILITEK_ILI9340_0_RESET_GPIOS_PIN,
                       GPIO_OUTPUT);

    data->command_data_gpio =
        device_get_binding(DT_ILITEK_ILI9340_0_CMD_DATA_GPIOS_CONTROLLER);
    if (data->command_data_gpio == NULL) {
        return -EPERM;
    }

    gpio_pin_configure(data->command_data_gpio,
                       DT_ILITEK_ILI9340_0_CMD_DATA_GPIOS_PIN, GPIO_OUTPUT);

    LOG_DBG("Resetting display driver\n");
    gpio_pin_set(data->reset_gpio, DT_ILITEK_ILI9340_0_RESET_GPIOS_PIN, 1);
    k_sleep(Z_TIMEOUT_MS(1));
    gpio_pin_set(data->reset_gpio, DT_ILITEK_ILI9340_0_RESET_GPIOS_PIN, 0);
    k_sleep(Z_TIMEOUT_MS(1));
    gpio_pin_set(data->reset_gpio, DT_ILITEK_ILI9340_0_RESET_GPIOS_PIN, 1);
    k_sleep(Z_TIMEOUT_MS(5));

    LOG_DBG("Initializing LCD\n");
    ili9340_lcd_init(data);

    LOG_DBG("Exiting sleep mode\n");
    ili9340_exit_sleep(data);

    return 0;
}

static void
ili9340_set_mem_area(struct ili9340_data *data, const u16_t x, const u16_t y,
                     const u16_t w, const u16_t h)
{
    u16_t spi_data[2];

    spi_data[0] = sys_cpu_to_be16(x);
    spi_data[1] = sys_cpu_to_be16(x + w - 1);
    ili9340_transmit(data, ILI9340_CMD_COLUMN_ADDR, &spi_data[0], 4);

    spi_data[0] = sys_cpu_to_be16(y);
    spi_data[1] = sys_cpu_to_be16(y + h - 1);
    ili9340_transmit(data, ILI9340_CMD_PAGE_ADDR, &spi_data[0], 4);
}

static int
ili9340_write(const struct device *dev, const u16_t x, const u16_t y,
              const struct display_buffer_descriptor *desc, const void *buf)
{
    struct ili9340_data *data = (struct ili9340_data *)&ili9340_data1;
    const u8_t *write_data_start = (u8_t *)buf;
    struct spi_buf tx_buf;
    struct spi_buf_set tx_bufs;
    u16_t write_cnt;
    u16_t nbr_of_writes;
    u16_t write_h;

    __ASSERT(desc->width <= desc->pitch, "Pitch is smaller then width");
    __ASSERT((3 * desc->pitch * desc->height) <= desc->buf_size,
             "Input buffer to small");
    ili9340_set_mem_area(data, x, y, desc->width, desc->height);

    if (desc->pitch > desc->width) {
        write_h = 1U;
        nbr_of_writes = desc->height;
    }
    else {
        write_h = desc->height;
        nbr_of_writes = 1U;
    }
    ili9340_transmit(data, ILI9340_CMD_MEM_WRITE, (void *)write_data_start,
                     3 * desc->width * write_h);

    tx_bufs.buffers = &tx_buf;
    tx_bufs.count = 1;

    write_data_start += (3 * desc->pitch);
    for (write_cnt = 1U; write_cnt < nbr_of_writes; ++write_cnt) {
        tx_buf.buf = (void *)write_data_start;
        tx_buf.len = 3 * desc->width * write_h;
        spi_transceive(data->spi_dev, &data->spi_config, &tx_bufs, NULL);
        write_data_start += (3 * desc->pitch);
    }

    return 0;
}

static int
ili9340_read(const struct device *dev, const u16_t x, const u16_t y,
             const struct display_buffer_descriptor *desc, void *buf)
{
    LOG_ERR("Reading not supported\n");
    return -ENOTSUP;
}

static void *
ili9340_get_framebuffer(const struct device *dev)
{
    LOG_ERR("Direct framebuffer access not supported\n");
    return NULL;
}

static int
ili9340_display_blanking_off(const struct device *dev)
{
    struct ili9340_data *data = (struct ili9340_data *)dev->driver_data;

    LOG_DBG("Turning display blanking off\n");
    ili9340_transmit(data, ILI9340_CMD_DISPLAY_ON, NULL, 0);
    return 0;
}

static int
ili9340_display_blanking_on(const struct device *dev)
{
    struct ili9340_data *data = (struct ili9340_data *)dev->driver_data;

    LOG_DBG("Turning display blanking on\n");
    ili9340_transmit(data, ILI9340_CMD_DISPLAY_OFF, NULL, 0);
    return 0;
}

static int
ili9340_set_brightness(const struct device *dev, const u8_t brightness)
{
    LOG_WRN("Set brightness not implemented\n");
    return -ENOTSUP;
}

static int
ili9340_set_contrast(const struct device *dev, const u8_t contrast)
{
    LOG_ERR("Set contrast not supported\n");
    return -ENOTSUP;
}

static int
ili9340_set_pixel_format(const struct device *dev,
                         const enum display_pixel_format pixel_format)
{
    if (pixel_format == PIXEL_FORMAT_RGB_888) {
        return 0;
    }
    LOG_ERR("Pixel format change not implemented\n");
    return -ENOTSUP;
}

static int
ili9340_set_orientation(const struct device *dev,
                        const enum display_orientation orientation)
{
    if (orientation == DISPLAY_ORIENTATION_NORMAL) {
        return 0;
    }
    LOG_ERR("Changing display orientation not implemented\n");
    return -ENOTSUP;
}

static void
ili9340_get_capabilities(const struct device *dev,
                         struct display_capabilities *capabilities)
{
    memset(capabilities, 0, sizeof(struct display_capabilities));
    capabilities->x_resolution = 320;
    capabilities->y_resolution = 240;
    capabilities->supported_pixel_formats = PIXEL_FORMAT_RGB_888;
    capabilities->current_pixel_format = PIXEL_FORMAT_RGB_888;
    capabilities->current_orientation = DISPLAY_ORIENTATION_NORMAL;
}

void
ili9340_transmit(struct ili9340_data *data, u8_t cmd, void *tx_data,
                 size_t tx_len)
{
    data = (struct ili9340_data *)&ili9340_data1;
    struct spi_buf tx_buf = { .buf = &cmd, .len = 1 };
    struct spi_buf_set tx_bufs = { .buffers = &tx_buf, .count = 1 };

    gpio_pin_set(data->command_data_gpio,
                 DT_ILITEK_ILI9340_0_CMD_DATA_GPIOS_PIN,
                 ILI9340_CMD_DATA_PIN_COMMAND);
    spi_transceive(data->spi_dev, &data->spi_config, &tx_bufs, NULL);
    if (tx_data != NULL) {
        tx_buf.buf = tx_data;
        tx_buf.len = tx_len;
        gpio_pin_set(data->command_data_gpio,
                     DT_ILITEK_ILI9340_0_CMD_DATA_GPIOS_PIN,
                     ILI9340_CMD_DATA_PIN_DATA);
        spi_transceive(data->spi_dev, &data->spi_config, &tx_bufs, NULL);
    }
}

struct display_driver_api ili9340_api1 = {
    .blanking_on = ili9340_display_blanking_on,
    .blanking_off = ili9340_display_blanking_off,
    .write = ili9340_write,
    .read = ili9340_read,
    .get_framebuffer = ili9340_get_framebuffer,
    .set_brightness = ili9340_set_brightness,
    .set_contrast = ili9340_set_contrast,
    .get_capabilities = ili9340_get_capabilities,
    .set_pixel_format = ili9340_set_pixel_format,
    .set_orientation = ili9340_set_orientation
};

/*
 DEVICE_AND_API_INIT(ili9340, DT_ILITEK_ILI9340_0_LABEL, &ili9340_init,
 &ili9340_data, NULL, APPLICATION,
 CONFIG_APPLICATION_INIT_PRIORITY, &ili9340_api);
 */
