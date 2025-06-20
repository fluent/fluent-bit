project(opentelemetry-utils C)

# include_directories(${CMAKE_CURRENT_SOURCE_DIR})
# include_directories(${PROJECT_SOURCE_DIR}/plugins/in_opentelemetry)

set(src
  flb_opentelemetry_logs.c
  flb_opentelemetry_utils.c
)

add_library(flb-opentelemetry-utils STATIC ${src})
