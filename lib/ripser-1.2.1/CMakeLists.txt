add_library(flb-ripser STATIC
    ripser.cpp          # upstream
    # ripser_wrapper.cpp
)

target_include_directories(flb-ripser
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}   # ripser_wrapper.h
)

target_compile_features(flb-ripser PUBLIC cxx_std_11)
