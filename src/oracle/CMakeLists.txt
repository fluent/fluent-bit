include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
)

set(src
        "flb_oracle_client.c"
        )

add_library(flb-oracle STATIC ${src})
target_link_libraries(flb-oracle)