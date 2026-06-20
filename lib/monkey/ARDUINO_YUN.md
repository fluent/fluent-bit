# Monkey + Arduino YUN toolchain

Short instructions to build with Arduino YUN toolchain:

## Get the toolchain

```shell
$ git clone https://github.com/MatteoRagni/ArduinoYun-x86_64-OpenWRT-mips-linux-toolchain.git
```

The content downloaded is the toolchain required, the absolute path of this directory is required in the next step:

### Compile Monkey

Make sure to replace the right values for CMAKE_INSTALL_PREFIX and _YUN_ROOT_:

```
$ rm -rf monkey/build
$ cd monkey/build
$ cmake -DCMAKE_TOOLCHAIN_FILE=cmake/arduino-yun.cmake \
        -DWITH_SYSTEM_MALLOC=ON -DWITH_BACKTRACE=OFF   \
        -DCMAKE_INSTALL_PREFIX=/opt/monkey             \
        -DYUN_ROOT=/path/to/ArduinoYun-x86_64-OpenWRT-mips-linux-toolchain \
        ../
$ make
$ make install
```
