cmake_minimum_required(VERSION 2.8)

project(wgl)

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../)

include_directories(
    ${WAMR_ROOT_DIR}/wamr-sdk/out/gui/app-sdk/wamr-app-framework/include
    ${WAMR_ROOT_DIR}/core/deps
)

set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS},-L${WAMR_ROOT_DIR}/wamr-sdk/out/gui/app-sdk/wamr-app-framework/lib")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS},--export=on_init,--export=on_timer_callback,--export=on_widget_event,--export=__heap_base,--export=__data_end")
set (CMAKE_C_FLAGS          "${CMAKE_C_FLAGS} -O3 -Wno-unused-command-line-argument")

add_executable(ui_increase.wasm
    ${CMAKE_CURRENT_LIST_DIR}/src/main.c
)

target_link_libraries(ui_increase.wasm  app_framework)
