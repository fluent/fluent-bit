### Build Docker Image

-   Linux

    ```shell
    ./build_docker_image.sh
    ```

-   Windows

    ```shell
    ./build_docker_image.bat
    ```


### Resource Details

-   `Dockerflie` is the source file to build `wasm-debug-server` docker image
-   `resource/debug.sh` is the script to execute the wasm app in debug mod, will start up the debugger server inside of the `iwasm` and hold to wait for connecting.
-   `resource/run.sh` is the script to execute the wasm app directly.
