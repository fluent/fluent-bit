# luajit-cmake

A flexible cmake builder for LuaJIT. Forked from
https://github.com/WohlSoft/LuaJIT and update.

## Build

### make 

Use a GNU compatible make.

`make -DLUAJIT_DIR=...` or `mingw32-make -DLUAJIT_DIR=...` or `gnumake -DLUAJIT_DIR=...`.

_Note_: When use mingw32-make, please change `\\` to `/` in file path on Windows.

### cmake

Use cmake to compile.

```
cmake -H. -Bbuild -DLUAJIT_DIR=...
make --build build --config Release
```

### CrossCompile

#### iOS

```
make iOS
```

#### Android

```
make Android
```

#### Windows

```
make Windows
```

#### Note

_Note_: The i386 architecture is deprecated for macOS (remove from the Xcode build setting: ARCHS). So I use mingw-w64 and wine to build and run 32 bits minilua and buildvm.

