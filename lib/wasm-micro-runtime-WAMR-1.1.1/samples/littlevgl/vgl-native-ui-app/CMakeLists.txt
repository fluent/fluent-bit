# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 2.9)
message ("vgl_native_ui_app...")
project (vgl_native_ui_app)


SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -DPLATFORM_NATIVE_LINUX -DUSE_MONITOR -DUSE_MOUSE=1")

# Currently build as 64-bit by default. Set to "NO" to build 32-bit binaries.
set (BUILD_AS_64BIT_SUPPORT "YES")

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
  if (${BUILD_AS_64BIT_SUPPORT} STREQUAL "YES")
    # Add -fPIC flag if build as 64-bit
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
    set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "${CMAKE_SHARED_LIBRARY_LINK_C_FLAGS} -fPIC")
  else ()
    add_definitions (-m32)
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
    set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")
  endif ()
endif ()

set(lv_name lvgl)
set(LVGL_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../build/lvgl)
set(LVGL_DRIVER_DIR ${CMAKE_CURRENT_LIST_DIR}/lv-drivers)

message(${LVGL_SOURCE_DIR})
include( ExternalProject )

add_definitions(-DLV_CONF_INCLUDE_SIMPLE)

SET (LVGL_SOURCES
    ${LVGL_SOURCE_DIR}/lv_core/lv_group.c
    ${LVGL_SOURCE_DIR}/lv_core/lv_indev.c
    ${LVGL_SOURCE_DIR}/lv_core/lv_lang.c
    ${LVGL_SOURCE_DIR}/lv_core/lv_obj.c
    ${LVGL_SOURCE_DIR}/lv_core/lv_refr.c
    ${LVGL_SOURCE_DIR}/lv_core/lv_style.c
    ${LVGL_SOURCE_DIR}/lv_core/lv_vdb.c

    ${LVGL_SOURCE_DIR}/lv_draw/lv_draw.c
    ${LVGL_SOURCE_DIR}/lv_draw/lv_draw_arc.c
    ${LVGL_SOURCE_DIR}/lv_draw/lv_draw_img.c
    ${LVGL_SOURCE_DIR}/lv_draw/lv_draw_label.c
    ${LVGL_SOURCE_DIR}/lv_draw/lv_draw_line.c
    ${LVGL_SOURCE_DIR}/lv_draw/lv_draw_rbasic.c
    ${LVGL_SOURCE_DIR}/lv_draw/lv_draw_rect.c
    ${LVGL_SOURCE_DIR}/lv_draw/lv_draw_triangle.c
    ${LVGL_SOURCE_DIR}/lv_draw/lv_draw_vbasic.c

    ${LVGL_SOURCE_DIR}/lv_hal/lv_hal_disp.c
    ${LVGL_SOURCE_DIR}/lv_hal/lv_hal_indev.c
    ${LVGL_SOURCE_DIR}/lv_hal/lv_hal_tick.c

    ${LVGL_SOURCE_DIR}/lv_misc/lv_anim.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_area.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_circ.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_color.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_font.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_fs.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_gc.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_ll.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_log.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_math.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_mem.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_task.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_templ.c
    ${LVGL_SOURCE_DIR}/lv_misc/lv_txt.c

    ${LVGL_SOURCE_DIR}/lv_objx/lv_arc.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_bar.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_btn.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_btnm.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_calendar.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_canvas.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_cb.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_chart.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_cont.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_ddlist.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_gauge.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_img.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_imgbtn.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_kb.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_label.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_led.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_line.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_list.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_lmeter.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_mbox.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_objx_templ.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_page.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_preload.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_roller.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_slider.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_spinbox.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_sw.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_ta.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_table.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_tabview.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_tileview.c
    ${LVGL_SOURCE_DIR}/lv_objx/lv_win.c

    ${LVGL_SOURCE_DIR}/lv_themes/lv_theme.c
    ${LVGL_SOURCE_DIR}/lv_themes/lv_theme_alien.c
    ${LVGL_SOURCE_DIR}/lv_themes/lv_theme_default.c
    ${LVGL_SOURCE_DIR}/lv_themes/lv_theme_material.c
    ${LVGL_SOURCE_DIR}/lv_themes/lv_theme_mono.c
    ${LVGL_SOURCE_DIR}/lv_themes/lv_theme_nemo.c
    ${LVGL_SOURCE_DIR}/lv_themes/lv_theme_night.c
    ${LVGL_SOURCE_DIR}/lv_themes/lv_theme_templ.c
    ${LVGL_SOURCE_DIR}/lv_themes/lv_theme_zen.c

    ${LVGL_SOURCE_DIR}/lv_fonts/lv_font_builtin.c
    ${LVGL_SOURCE_DIR}/lv_fonts/lv_font_dejavu_20.c
    ${LVGL_DRIVER_DIR}/linux_display_indev.c
    ${LVGL_DRIVER_DIR}/indev/mouse.c

)
SET(SOURCES
    ${LVGL_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/main.c
    )
include_directories(
    ${LVGL_DRIVER_DIR}
    ${LVGL_DRIVER_DIR}/display
    ${LVGL_DRIVER_DIR}/indev
    ${LVGL_SOURCE_DIR}
    ${LVGL_SOURCE_DIR}/..
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../lv_config
)
add_executable(vgl_native_ui_app ${SOURCES} )
target_link_libraries( vgl_native_ui_app -lSDL2)
