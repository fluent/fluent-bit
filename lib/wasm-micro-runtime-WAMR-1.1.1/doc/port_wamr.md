
WAMR porting guide
=========================


This document describes how to port WAMR to a new platform "**new-os**"



# Step 1: Implement platform API layer

-------------------------
Firstly create the folder **`core/shared/platform/new-os`** for platform API layer implementations. In the folder you just created, you must provide the following files:

- `platform_internal.h`: It can be used for any platform specific definitions such as macros, data types and internal APIs.

- `shared_platform.cmake`: the cmake file will be included by the building script. It is recommended to add a definition for your platform:

  - ```cmake
    add_definitions(-DBH_PLATFORM_YOUR_NAME)
    ```

Then go to implement the APIs defined in following header files for the platform abstraction layer:

- [`platform_api_vmcore.h`](../core/shared/platform/include/platform_api_vmcore.h):   mandatory for building mini-product (vmcore only). Part of APIs are needed only for Ahead of Time compilation support. 
- [`platform_api_extension.h`](../core/shared/platform/include/platform_api_extension.h): mandatory for app-mgr and app-framework. Given that the app-mgr and app-framework are not required for your target platform, you won't have to implement the API defined in the `platform_api_extension.h`.



**common/posix:**

There is posix based implementation of the platform API located in the `platform/common/posix` folder. You can include it if your platform support posix API. refer to platform linux implementation.



**common/math:**

Some platforms such as ZephyrOS don't provide math functions e.g. sqrt, fabs and isnan, then you should include source files under the folder `platform/common/math`. 



# Step 2: Create the mini product for the platform

-------------------------
You can build a mini WAMR product which is only the vmcore for you platform. Normally you need to implement the main function which loads a WASM file and run it with the WASM runtime. You don't have to do this step if there is no mini-product need for your platform porting.



Firstly create folder **product-mini/platforms/new-os** for the platform mini product build, then refer to the linux platform mini-product for creating the CMakeList.txt and the C implementations.



You should set cmake variable `WAMR_BUILD_PLATFORM` to your platform name while building the mini product. It can be done in the mini product CMakeList.txt file, or pass  arguments to cmake command line like:

```
mkdir build
cd build
cmake .. -DWAMR_BUILD_PLATFORM=new-os 
```



Refer to [build_wamr.md](./build_wamr.md) for the building configurations and parameters.



