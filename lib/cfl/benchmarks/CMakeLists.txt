add_executable(cfl-benchmark-variant-arena arena.c)
target_link_libraries(cfl-benchmark-variant-arena cfl-static)

add_executable(cfl-benchmark-variant-mutable variant_mutable.c)
target_link_libraries(cfl-benchmark-variant-mutable cfl-static)
