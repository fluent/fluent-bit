# WAMR-IDE (Experimental)

## Introduction

The WAMR-IDE is an Integrated Development Environment to develop WebAssembly application with coding, compiling and source debugging support. It contains 3 components: `VSCode extension`, `wasm-toolchain docker image` and `wasm-debug-server docker image`.

- `VSCode extension` is an `vscode` extension, with which user can build and manage projects, develop `wasm application`, including `building`, `running` and `debugging`.

- `WASM-toolchain` is a docker image which provides building environment for wasm.

- `WASM source debug server` is a docker image which provides running and source debugging environment for wasm application.

---

## How to setup WAMR IDE

Now, the most straightforward way to install the WAMR IDE extension is by searching for WAMR-IDE in the VS Code extension marketplace and installing it directly. So, if you simply want to use WAMR debugging features in VS Code, this is the ideal (and effortless) way. And you are ready to [use WAMR IDE](#how-to-use-wamr-ide).

> It is only recommended to download versions after 1.3.2 from the marketplace.

Also, we have same version tagged docker images, lldb binaries and VS Code installation file(.vsix file) packed for each GitHub release. You can following the tutorial in [this section](#21-download-wamr-vs-code-extension-from-the-github-releaserecommended-approach).

Alternatively, if you want to build lldb, docker images, or .vsix file locally so that you can try the effect of your modification, you could refer to the tutorial in [this section](#22-build-wamr-vs-code-extension-locallyalternative-approach).

### 1. Preparation

#### 1.1. Install `VSCode` on host

- make sure the version of [vscode](https://code.visualstudio.com/Download) you installed is at least _1.59.0_

#### 1.2. Install `Docker` on host

    1. [Windows: Docker Desktop](https://docs.docker.com/desktop/windows/install/)
    2. [Ubuntu: Docker Engine](https://docs.docker.com/engine/install/ubuntu)
       ```xml
       OS requirements:
       To install Docker Engine, you need the 64-bit version of one of these Ubuntu versions:
       - Ubuntu Impish 21.10
       - Ubuntu Hirsute 21.04
       - Ubuntu Focal 20.04(LTS)
       - Ubuntu Bionic 18.04(LTS)
       ```

### 2. WAMR VS Code extension: download from the GitHub release or build locally

#### 2.1 Download WAMR VS Code extension from the GitHub release(Recommended approach)

##### 2.1.1 Load docker images from the GitHub release tar file

From now on, for each GitHub release, we have the same version tagged docker image saved as a tar file, which you can find and download in the GitHub release.

You could download the tar archive files for docker images from the release, and then load them using the following commands:

```sh
# download the zip or tar.gz from release depending on your platform
# decompress and get the tar file

# on Linux/MacOS, you could use tar
tar xf wasm-toolchain-{version number}.tar.gz
tar xf wasm-debug-server-{version number}.tar.gz
# or you could use unzip
unzip wasm-toolchain-{version number}.zip
unzip wasm-debug-server-{version number}.zip
# load wasm-toolchain
docker load --input wasm-toolchain.tar
# load wasm-debug-server
docker load --input wasm-debug-server.tar

# on Windows, you could use any unzip software you like
# then loading docker images using powershell or git bash
# load wasm-toolchain
docker load --input ./wasm-toolchain.tar
# load wasm-debug-server
docker load --input ./wasm-debug-server.tar
```

##### 2.1.2 Download the VS Code extension installation file from the GitHub release

From now on, for each GitHub release, we have the same version tagged zip/tar.gz file. For example, in release version 1.1.2, you can easily download and decompress `wamr-ide-1.1.2.tar.gz` `wamr-ide-1.1.2.zip`, which contains `wamr-ide.vsix` VS Code extension installation file. As you can imagine, in the future, when new releases are available, you can freely choose whichever version(for example, 1.2.0, 1.3.0, etc.) you prefer. It should work as long as you download the same version tagged docker image and .vsix file.

##### 2.1.3 Install extension from vsix

![install_from_vsix](./Media/install_from_vsix.png "install wamr-ide from vsix")

select `wamr-ide.vsix` which you have decompressed from `.tar.gz` or `.zip` file.

#### 2.2 Build WAMR VS Code extension locally(Alternative approach)

You could also build the VS Code extension locally, the following instruction provides a thorough tutorial. It's worth noting that in the local build tutorial we use hard-coded tag version 1.0 other than the semantic version of WAMR.

Note: Please ensure that the scripts under `resource` directories have execution permission. While on git they have x bits, you might have dropped them eg. by copying them from Windows. Similarly, do not drop execution permission when copying `lldb` binaries under `resource/debug/bin`.

##### 2.2.1 Build docker images on host

We have 2 docker images which should be built or loaded on your host, `wasm-toolchain` and `wasm-debug-server`. To build these 2 images, please enter the `WASM-Debug-Server/Docker` & `WASM-Toolchain/Docker`, then execute the `build_docker_image` script respectively.

Windows (powershell):

```batch
cd .\WASM-Toolchain\Docker
.\build_docker_image.bat
cd .\WASM-Debug-Server\Docker
.\build_docker_image.bat
```

Linux:

```shell
cd ./WASM-Toolchain/Docker
./build_docker_image.sh
cd ./WASM-Debug-Server/Docker
./build_docker_image.sh
```

##### 2.2.2 After building, you can find `wasm-toolchain` and `wasm-debug-server` docker images on your local

![docker-images](./Media/docker_images.png)

##### 2.2.3 If building docker images fail during the process

Sometimes building the Docker images may fail due to bad network conditions. If the `wasm-toolchain` and `wasm-debug-server` images do not exist after building, please build them manually. Fix the proxy setting if needed and execute the following command to build docker images.

![docker-engine-config](./Media/docker_config.jpg)

> Note: please correctly replace example proxy address with your own before you run manually.

```xml
$ cd .\docker_images\wasm-debug-server
$ docker build --no-cache --build-arg http_proxy=http://proxy.example.com:1234
--build-arg https_proxy=http://proxy.example.com:1234 -t wasm-debug-server:1.0 .
```

```xml
$ cd .\docker_images\wasm-toolchain
$ docker build --no-cache --build-arg http_proxy=http://proxy.example.com:1234
--build-arg https_proxy=http://proxy.example.com:1234 -t wasm-toolchain:1.0 .
```

##### 2.2.4 If you encounter the problem `failed to solve with frontend dockerfile.v0: failed to create LLB definition`, please config your docker desktop

![docker-engine-config](./Media/docker_engine_config.png)

##### 2.2.5 Points To Remember

- Make sure that the `wasm-toolchain:1.0` and `wasm-debug-server:1.0` docker images are both successfully built before using `WAMR IDE`, otherwise `Build`, `Run` and `Debug` will not work.

##### 2.2.6 Generate wamride extension package file

`wamride-1.0.0.vsix` can be packaged by [`npm vsce`](https://code.visualstudio.com/api/working-with-extensions/publishing-extension).

```shell
npm install -g vsce
cd VSCode-Extension
rm -rf node_modules
npm install
vsce package
```

##### 2.2.7 Enable VS Code debugging feature

By default, when you build .vsix locally, the debugging feature is off. Suppose you want to enable the source debugging feature. In that case, you could download `lldb` binaries from our GitHub release (for example, `wamr-lldb-1.1.2-x86_64-ubuntu-20.04.tar.gz`), decompress and put every subdirectory and file to the installed directory of your VS Code extension.

For example, let's say you are on an Ubuntu 20.04 machine. You first download and decompress `wamr-lldb-1.1.2-x86_64-ubuntu-20.04.tar.gz`, and you will get a `wamr-lldb` folder (or `inst` folder in our earlier release). Then, you can simply copy the files and directory inside that folder to the relative path `resource/debug/linux/` under your VS Code extension installation directory.

Example commands on an Ubuntu 20.04 machine:

```shell
# decompress .tar.gz file and get the folder
$ ls wamr-lldb
bin  lib  package.json  syntaxes
# copy everything to the vscode extension installation path(in this case, it's /home/{usrname}/.vscode-server/extensions/wamr.wamride-1.0.0/)
$ cp inst/* /home/{usrname}/.vscode-server/extensions/wamr.wamride-1.0.0/resource/debug/linux/
```

If you want to use your own patched `lldb`, you could follow this [instruction](../../doc/source_debugging.md#debugging-with-interpreter) to build `lldb`. And follow this [instruction](./VSCode-Extension/resource/debug/README.md)
to copy the binaries to replace the existing ones.

> **You can also debug the extension directly follow this [instruction](./VSCode-Extension/README.md) without packing the extension.**

##### 2.2.7 Install extension from vsix

![install_from_vsix](./Media/install_from_vsix.png "install wamr-ide from vsix")

select `wamride-1.0.0.vsix` which you have packed on your host.

---

## How to use `wamr-ide`

#### `WAMR-IDE` extension contains 2 components as following picture showing. `WAMR IDE` for workspace and project management and `Current Project` for project's execution

![wamr_ide_main_menu](./Media/wamr_ide_main_menu.png "wamr-ide main menu")

### Project Execution

#### 1. New project

When you click `New project` button, the extension will pop up a message box at the bottom right of the screen as following:

![set-up-workspace-message](./Media/set_up_workspace_message.png "set up workspace message box")

You can click `Set up now` and select the target folder to create project workspace, or you click `Maybe later` to close the message box.

> Note that your selected workspace folder should be **empty** or the folder you have set up as workspace.

After setting up workspace, extension will prompt successful message:

```xml
Workspace has been set up successfully!
```

Then click `New project` button again, a new page will show as following.

![new-project-page](./Media/new_project_page.png "new project page")

Enter the `Project name` and select the `Template`, then click `Create` button. A new project will be generated and opened in your current `VS Code window` or in a new `VS Code window`.

> Opening in current windows or a new one depends on whether your `vscode's explorer` is empty or not. If empty, open in current window, or open in the new vscode window.

A new initialized project is as following picture shows.

![project-template](./Media/project_template.png "default project template")

`.wamr` is the project configuration folder which contains 3 files, `CMakeLists.txt`, `project.cmake`, and `compilation_config.json`. `CMakeLists.txt` is used to build `wasm target` and the `project.cmake` is included in `CMakeLists.txt`. `compilation_config.json` includes the user's customized configuration such as folders which should be added in the include path.

#### 2. Open project

Click `Open project` button, `quick-pick-box` will show as following. All projects under your current workspace will be shown and can be selected.

![configuration file](./Media/open_project_page.png "configuration file")

#### 3. Change workspace

Click `Change workspace` button, a dialog will show as following. You can select 1 folder in file system as workspace, and the new workspace path will override previous workspace, and all new created projects will be generated in the new workspace.

![change workspace ](./Media/change_workspace_dialog.png "change workspace dialog")

#### 4. Customize `include paths` and `exclude source files`

    Extension supports adding header file folder to `include path` and excluding source file from build.

- `Add to include path`

  - Move the cursor to the `folder` and right click, then `menus` will be shown as following. Click `Toggle state of path including`.

  ![right click menus](./Media/right_click_menus_1.png "right click menus")

- `Exclude source file from build`

  - Move the cursor to the `source file` and right click, then `menus` will be shown as following. Click `Toggle state of excluding`.

  ![right click menus](./Media/right_click_menus_2.png "right click menus")

#### After setting up `include path` and `exclude files`, the corresponding folder and files will be decorated with color and icon as following picture shows

  ![decoration for files](./Media/decoration_for_files.png "decoration for files")

  At the same time, all added `include path` and `exclude files` will be saved in `.wamr/compilation_config.json` as json array.

  ![compilation config](./Media/compilation_config.png "compilation config")

> `Toggle state of path including` just shows when selecting `folder` and hides with other resources.
>
> `Toggle state of excluding` just shows when selecting `[.c | .cpp | .cxx] source files` and hides with other resources.

### Current Project Management

#### 1. Configuration

Click `Configuration` button, a new page will be shown as following. You can config building target with `Include paths`, `Initial & Max linear memory`, `stack size`, `exported_symbols` and `include paths`, `exclude files`.

![config building target](./Media/Config_building_target.png "config building target")

Short Explanation of the Fields Above:

- Output file name: The compiled wasm file name of your program.
- Initial linear memory size, Max linear memory size, Stack size: The wasi-sdk clang compile options.
- Exported symbols: The symbols your wasm program wants to export. **Multiple symbols are separated by commas without spaces**.
- Host managed heap size: The running configuration for the host managed heap size of iwasm. In most cases, the default size would be fine, but in some scenarios, let's say you want to allocate more memory using `malloc`, you should increase it here accordingly.

> Note that due to the current implementation limitation, after changing the `Output file name` or `Host managed heap size`, you need to close and reopen VSCode (to reactivate the extension) so that the running config will be correctly updated.

Then click `Modify` button to confirm, if configurations are modified successfully and following message will pop. Click `OK`, the page will be auto closed.

![save configuration](./Media/save_configuration.png "save configuration")

And all configuration will be saved in `.wamr/compilation_config.json`.

![configuration file](./Media/compilation_config_2.png "configuration file")

#### 2. `Build`

When you have completed coding and ready to build target, click `build` button and the `wasm-toolchain` will auto start a container and execute the building process.

![build terminal output](./Media/build_terminal.png "build terminal output")

After successful building execution, `build` folder will be generated in `explorer`, in which `${output_file_name}.wasm` is exist.

![build folder](./Media/build_folder.png "build folder")

> Note that to start `docker service` firstly.

#### 3. Run

Click `Run` button and `wasm-debug-server` docker image will auto start a container and execute the running process.

![run](./Media/run.png "run wasm")

#### 4. Debug

Click `Debug` button will trigger start ip `wamr-debug-server` docker image, and boot up `lldb debug server` inside of iwasm. Then start a debugging session with configuration to connect. Tap `F11` or click `step into` to start debugging.

![debug](./Media/debug.png "source debugging")

> Docker containers will be auto stopped and removed after the execution.
