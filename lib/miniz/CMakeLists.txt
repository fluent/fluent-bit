set(src
  miniz.c)

# Tweak Miniz library
add_definitions("-DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_STDIO -DMINIZ_NO_TIME")

add_library(miniz STATIC ${src})
