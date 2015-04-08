This directory contains example configuration files.

The examples are generally focused on a particular usage case (eg, support for
a restricted number of ciphersuites) and aim at minimizing resource usage for
this target. They can be used as a basis for custom configurations.

These files are complete replacements for the default config.h. To use one of
them, you can pick one of the following methods:

1. Replace the default file include/polarssl/config.h with the chosen one.
   (Depending on your compiler, you may need to ajust the line with
   #include "polarssl/check_config.h" then.)

2. Define POLARSSL_CONFIG_FILE and adjust the include path accordingly.
   For example, using make:

    CFLAGS="-I$PWD/configs -DPOLARSSL_CONFIG_FILE='<foo.h>'" make

   Or, using cmake:

    find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
    CFLAGS="-I$PWD/configs -DPOLARSSL_CONFIG_FILE='<foo.h>'" cmake .
    make

Note that the second method also works if you want to keep your custom
configuration file outside the mbed TLS tree.
