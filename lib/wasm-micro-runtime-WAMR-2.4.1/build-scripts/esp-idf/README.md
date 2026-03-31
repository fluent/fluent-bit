# wasm-micro-runtime as ESP-IDF component

You can build an ESP-IDF project with wasm-micro-runtime as a component:

- Make sure you have the ESP-IDF properly installed and setup
- In particular have the following paths set:
  - `WAMR_PATH` to point to your wasm-micro-runtime repository
  - `IDF_PATH` to point to your ESP-IDF
  - `source $IDF_PATH/export.sh`
- Create a new project, e.g.: `idf.py create-project wamr-hello`
- In the newly created project folder edit the `CMakeList.txt`:

  ```
  cmake_minimum_required(VERSION 3.14)

  include($ENV{IDF_PATH}/tools/cmake/project.cmake)

  set (COMPONENTS ${IDF_TARGET} main freertos esptool_py wamr)

  list(APPEND EXTRA_COMPONENT_DIRS "$ENV{WAMR_PATH}/build-scripts/esp-idf")

  project(wamr-hello)
  ```
- Develop your project in it's `main` component folder.

You can find an example [here](../../product-mini/platforms/esp-idf).

- Set target platform: `idf.py set-target esp32c3`
- Build: `idf.py build`
- Flash: `idf.py flash`
- Check the output: `idf.py monitor`