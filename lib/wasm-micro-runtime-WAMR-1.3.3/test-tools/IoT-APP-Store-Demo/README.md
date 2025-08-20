# IoT Application Store
Wasm application management portal for WAMR

## Start the server

### Using docker
1. install docker and docker-compose
    ``` bash
    sudo apt install docker.io docker-compose
    ```

2. start
    ``` bash
    docker-compose up
    ```
### Using commands
> Note: must use python3.5. If you don't have python3.5 on your machine, had better using docker
1. install the required package
    ``` bash
    pip3 install django
    ```

2. Start device server
    ``` bash
    cd wasm_django/server
    python3 wasm_server.py
    ```

3. Start IoT application management web portal
    ``` bash
    cd wasm_django
    python3 manage.py runserver 0.0.0.0:80
    ```

## Start the runtime
1. Download WAMR runtime from [help](http://localhost/help/) page
    > NOTE: You need to start the server before accessing this link!

2. Start a WAMR runtime from localhost
    ``` bash
    chmod +x simple
    ./simple
    ```
    or from other computers
    ``` bash
    ./simple -a [your.server.ip.address]
    ```

## Online demo
    http://82.156.57.236/
