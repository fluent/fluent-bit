# Remote application management

The WAMR application manager supports [remote application management](../../core/app-mgr) from the host environment or the cloud through any physical communications such as TCP, UPD, UART, BLE, etc. Its modular design makes it able to support application management for different managed runtimes.

The tool [host_tool](../../test-tools/host-tool) communicates to the WAMR app manager for installing/uninstalling the WASM applications on companion chip from the host system. And the [IoT App Store Demo](../../test-tools/IoT-APP-Store-Demo/) shows the conception of remotely managing the device applications from the cloud.


<img src="../../doc/pics/wamr-arch.JPG" width="80%">
