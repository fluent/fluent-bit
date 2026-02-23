add_library(ripser-static STATIC
    ripser.cpp          # upstream + patched version
)

target_include_directories(ripser-static
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}   # ripser_internal.hpp
)

target_compile_features(ripser-static PUBLIC cxx_std_11)
