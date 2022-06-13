### Build Docker Image

-   execute `build_docker_image.bat` on `Windows`
-   execute `build_docker_image.sh` on `Linux`

    ```shell
    chmod +x resource/*
    ./build_docker_image.sh
    ```

### Resource Details

-   `Dockerflie` is the source file to build `wasm-debug-server` docker image
-   `resource/debug.sh` is the script to execute the `/mnt/build/${target}.wasm` in debug mode, will start up the debugger server inside of the `iwasm` and hold to wait for connecting.
-   `resource/run.sh` is the script to execute the `/mnt/build/${target}.wasm` directly.
