/*
 * Copyright (c) 2017 Jan Van Winkel <jan.van_winkel@dxplore.eu>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public API for display drivers and applications
 */

#ifndef ZEPHYR_INCLUDE_DISPLAY_H_
#define ZEPHYR_INCLUDE_DISPLAY_H_

/**
 * @brief Display Interface
 * @defgroup display_interface Display Interface
 * @ingroup display_interfaces
 * @{
 */

#include <device.h>
#include <stddef.h>
#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum display_pixel_format {
    PIXEL_FORMAT_RGB_888 = BIT(0),
    PIXEL_FORMAT_MONO01 = BIT(1), /* 0=Black 1=White */
    PIXEL_FORMAT_MONO10 = BIT(2), /* 1=Black 0=White */
    PIXEL_FORMAT_ARGB_8888 = BIT(3),
    PIXEL_FORMAT_RGB_565 = BIT(4),
};

enum display_screen_info {
    /**
     * If selected, one octet represents 8 pixels ordered vertically,
     * otherwise ordered horizontally.
     */
    SCREEN_INFO_MONO_VTILED = BIT(0),
    /**
     * If selected, the MSB represents the first pixel,
     * otherwise MSB represents the last pixel.
     */
    SCREEN_INFO_MONO_MSB_FIRST = BIT(1),
    /**
     * Electrophoretic Display.
     */
    SCREEN_INFO_EPD = BIT(2),
    /**
     * Screen has two alternating ram buffers
     */
    SCREEN_INFO_DOUBLE_BUFFER = BIT(3),
};

/**
 * @enum display_orientation
 * @brief Enumeration with possible display orientation
 *
 */
enum display_orientation {
    DISPLAY_ORIENTATION_NORMAL,
    DISPLAY_ORIENTATION_ROTATED_90,
    DISPLAY_ORIENTATION_ROTATED_180,
    DISPLAY_ORIENTATION_ROTATED_270,
};

/**
 * @struct display_capabilities
 * @brief Structure holding display capabilities
 *
 * @var u16_t display_capabilities::x_resolution
 * Display resolution in the X direction
 *
 * @var u16_t display_capabilities::y_resolution
 * Display resolution in the Y direction
 *
 * @var u32_t display_capabilities::supported_pixel_formats
 * Bitwise or of pixel formats supported by the display
 *
 * @var u32_t display_capabilities::screen_info
 * Information about display panel
 *
 * @var enum display_pixel_format display_capabilities::current_pixel_format
 * Currently active pixel format for the display
 *
 * @var enum display_orientation display_capabilities::current_orientation
 * Current display orientation
 *
 */
struct display_capabilities {
    u16_t x_resolution;
    u16_t y_resolution;
    u32_t supported_pixel_formats;
    u32_t screen_info;
    enum display_pixel_format current_pixel_format;
    enum display_orientation current_orientation;
};

/**
 * @struct display_buffer_descriptor
 * @brief Structure to describe display data buffer layout
 *
 * @var u32_t display_buffer_descriptor::buf_size
 * Data buffer size in bytes
 *
 * @var u16_t display_buffer_descriptor::width
 * Data buffer row width in pixels
 *
 * @var u16_t display_buffer_descriptor::height
 * Data buffer column height in pixels
 *
 * @var u16_t display_buffer_descriptor::pitch
 * Number of pixels between consecutive rows in the data buffer
 *
 */
struct display_buffer_descriptor {
    u32_t buf_size;
    u16_t width;
    u16_t height;
    u16_t pitch;
};

/**
 * @typedef display_blanking_on_api
 * @brief Callback API to turn on display blanking
 * See display_blanking_on() for argument description
 */
typedef int (*display_blanking_on_api)(const struct device *dev);

/**
 * @typedef display_blanking_off_api
 * @brief Callback API to turn off display blanking
 * See display_blanking_off() for argument description
 */
typedef int (*display_blanking_off_api)(const struct device *dev);

/**
 * @typedef display_write_api
 * @brief Callback API for writing data to the display
 * See display_write() for argument description
 */
typedef int (*display_write_api)(const struct device *dev, const u16_t x,
                                 const u16_t y,
                                 const struct display_buffer_descriptor *desc,
                                 const void *buf);

/**
 * @typedef display_read_api
 * @brief Callback API for reading data from the display
 * See display_read() for argument description
 */
typedef int (*display_read_api)(const struct device *dev, const u16_t x,
                                const u16_t y,
                                const struct display_buffer_descriptor *desc,
                                void *buf);

/**
 * @typedef display_get_framebuffer_api
 * @brief Callback API to get framebuffer pointer
 * See display_get_framebuffer() for argument description
 */
typedef void *(*display_get_framebuffer_api)(const struct device *dev);

/**
 * @typedef display_set_brightness_api
 * @brief Callback API to set display brightness
 * See display_set_brightness() for argument description
 */
typedef int (*display_set_brightness_api)(const struct device *dev,
                                          const u8_t brightness);

/**
 * @typedef display_set_contrast_api
 * @brief Callback API to set display contrast
 * See display_set_contrast() for argument description
 */
typedef int (*display_set_contrast_api)(const struct device *dev,
                                        const u8_t contrast);

/**
 * @typedef display_get_capabilities_api
 * @brief Callback API to get display capabilities
 * See display_get_capabilities() for argument description
 */
typedef void (*display_get_capabilities_api)(
    const struct device *dev, struct display_capabilities *capabilities);

/**
 * @typedef display_set_pixel_format_api
 * @brief Callback API to set pixel format used by the display
 * See display_set_pixel_format() for argument description
 */
typedef int (*display_set_pixel_format_api)(
    const struct device *dev, const enum display_pixel_format pixel_format);

/**
 * @typedef display_set_orientation_api
 * @brief Callback API to set orientation used by the display
 * See display_set_orientation() for argument description
 */
typedef int (*display_set_orientation_api)(
    const struct device *dev, const enum display_orientation orientation);

/**
 * @brief Display driver API
 * API which a display driver should expose
 */
struct display_driver_api {
    display_blanking_on_api blanking_on;
    display_blanking_off_api blanking_off;
    display_write_api write;
    display_read_api read;
    display_get_framebuffer_api get_framebuffer;
    display_set_brightness_api set_brightness;
    display_set_contrast_api set_contrast;
    display_get_capabilities_api get_capabilities;
    display_set_pixel_format_api set_pixel_format;
    display_set_orientation_api set_orientation;
};
extern struct ili9340_data ili9340_data1;
extern struct display_driver_api ili9340_api1;
/**
 * @brief Write data to display
 *
 * @param dev Pointer to device structure
 * @param x x Coordinate of the upper left corner where to write the buffer
 * @param y y Coordinate of the upper left corner where to write the buffer
 * @param desc Pointer to a structure describing the buffer layout
 * @param buf Pointer to buffer array
 *
 * @retval 0 on success else negative errno code.
 */
static inline int
display_write(const struct device *dev, const u16_t x, const u16_t y,
              const struct display_buffer_descriptor *desc, const void *buf)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    return api->write(dev, x, y, desc, buf);
}

/**
 * @brief Read data from display
 *
 * @param dev Pointer to device structure
 * @param x x Coordinate of the upper left corner where to read from
 * @param y y Coordinate of the upper left corner where to read from
 * @param desc Pointer to a structure describing the buffer layout
 * @param buf Pointer to buffer array
 *
 * @retval 0 on success else negative errno code.
 */
static inline int
display_read(const struct device *dev, const u16_t x, const u16_t y,
             const struct display_buffer_descriptor *desc, void *buf)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    return api->read(dev, x, y, desc, buf);
}

/**
 * @brief Get pointer to framebuffer for direct access
 *
 * @param dev Pointer to device structure
 *
 * @retval Pointer to frame buffer or NULL if direct framebuffer access
 * is not supported
 *
 */
static inline void *
display_get_framebuffer(const struct device *dev)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    return api->get_framebuffer(dev);
}

/**
 * @brief Turn display blanking on
 *
 * @param dev Pointer to device structure
 *
 * @retval 0 on success else negative errno code.
 */
static inline int
display_blanking_on(const struct device *dev)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    return api->blanking_on(dev);
}

/**
 * @brief Turn display blanking off
 *
 * @param dev Pointer to device structure
 *
 * @retval 0 on success else negative errno code.
 */
static inline int
display_blanking_off(const struct device *dev)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    return api->blanking_off(dev);
}

/**
 * @brief Set the brightness of the display
 *
 * Set the brightness of the display in steps of 1/256, where 255 is full
 * brightness and 0 is minimal.
 *
 * @param dev Pointer to device structure
 * @param brightness Brightness in steps of 1/256
 *
 * @retval 0 on success else negative errno code.
 */
static inline int
display_set_brightness(const struct device *dev, u8_t brightness)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    return api->set_brightness(dev, brightness);
}

/**
 * @brief Set the contrast of the display
 *
 * Set the contrast of the display in steps of 1/256, where 255 is maximum
 * difference and 0 is minimal.
 *
 * @param dev Pointer to device structure
 * @param contrast Contrast in steps of 1/256
 *
 * @retval 0 on success else negative errno code.
 */
static inline int
display_set_contrast(const struct device *dev, u8_t contrast)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    return api->set_contrast(dev, contrast);
}

/**
 * @brief Get display capabilities
 *
 * @param dev Pointer to device structure
 * @param capabilities Pointer to capabilities structure to populate
 */
static inline void
display_get_capabilities(const struct device *dev,
                         struct display_capabilities *capabilities)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    api->get_capabilities(dev, capabilities);
}

/**
 * @brief Set pixel format used by the display
 *
 * @param dev Pointer to device structure
 * @param pixel_format Pixel format to be used by display
 *
 * @retval 0 on success else negative errno code.
 */
static inline int
display_set_pixel_format(const struct device *dev,
                         const enum display_pixel_format pixel_format)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    return api->set_pixel_format(dev, pixel_format);
}

/**
 * @brief Set display orientation
 *
 * @param dev Pointer to device structure
 * @param orientation Orientation to be used by display
 *
 * @retval 0 on success else negative errno code.
 */
static inline int
display_set_orientation(const struct device *dev,
                        const enum display_orientation orientation)
{
    struct display_driver_api *api = &ili9340_api1;
    //(struct display_driver_api *)dev->driver_api;

    return api->set_orientation(dev, orientation);
}

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_DISPLAY_H_*/
