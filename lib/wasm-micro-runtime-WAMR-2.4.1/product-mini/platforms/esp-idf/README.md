# How to Use WAMR with ESP-IDF

ESP-IDF is the official development framework for Espressif SoCs, supporting Windows, Linux, and macOS. WAMR (WebAssembly Micro Runtime) can be integrated as a standard [ESP-IDF](https://github.com/espressif/esp-idf) component.

## 1. Setup the ESP-IDF Development Environment

This example demonstrates how to use WAMR with ESP-IDF. Before proceeding, ensure you have the ESP-IDF development environment installed. For the relevant process, please refer to ESP-IDF [documents](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html).

### Prerequisites

#### Software Requirements

* ESP-IDF v4.4.0 and above.

#### Hardware Requirements

* A development board with one of the following SoCs:

  - ESP32

  - ESP32-C3

  - ESP32-S3

  - ESP32-C6

  - ESP32-P4

  - ESP32-C5

* See [Development Boards](https://www.espressif.com/en/products/devkits) for more information about it.

> Note: Different chips require different ESP-IDF versions, please check [ESP-IDF Release and SoC Compatibility](https://github.com/espressif/esp-idf?tab=readme-ov-file#esp-idf-release-and-soc-compatibility) before proceeding.

### Installation Steps

1. Navigate to the ESP-IDF root directory.

2. Run the installation script based on your OS:

  - Linux/MacOS

    ```
    ./install.sh
    ```

  - Windows

    ```
    ./install.bat
    ```

3. If successful, you should see:

    ```
    All done! You can now run:

      . ./export.sh
    ```

## 2. Compiling and Running the Project

### Set the Target Chip

Switch to the project directory and specify the target chip:

```bash
idf.py set-target <chip_name>
```

### Configure the project

Open the configuration menu: 

```bash
idf.py menuconfig
```

To modify WAMR settings, navigate to: `Component config -> WASM Micro Runtime`

### Build and Flash

Run the following command to compile, flash, and monitor the application:

```bash
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

See the [Getting Started Guide](https://idf.espressif.com/) for full steps to configure and use ESP-IDF to build projects.