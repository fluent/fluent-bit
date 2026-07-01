# luajit-cmake

A flexible cmake builder for LuaJIT. Forked from
[WohlSoft/LuaJIT](https://github.com/WohlSoft/LuaJIT) and update.

## Build

### make

Use a GNU compatible make.

`make -DLUAJIT_DIR=...` or `mingw32-make -DLUAJIT_DIR=...` or
`gnumake -DLUAJIT_DIR=...`.

_Note_: When use mingw32-make, please change `\\` to `/` in file path on Windows.

### cmake

Use cmake to compile.

```bash
cmake -H. -Bbuild -DLUAJIT_DIR=...
make --build build --config Release
```

### Embed

```cmake
add_subdirectory(luajit-cmake)
target_link_libraries(yourTarget PRIVATE luajit::lib luajit::header)
```

Look samples at [lua-forge](https://github.com/zhaozg/lua-forge/blob/master/CMakeLists.txt)

### CrossCompile

#### iOS

```bash
make iOS
```

#### Android

```bash
make Android
```

#### Windows

```bash
make Windows
```

#### Note

_Note_: The i386 architecture is deprecated for macOS (remove from the Xcode
build setting: ARCHS). So I use mingw-w64 and wine to build and run 32 bits
minilua and buildvm.
