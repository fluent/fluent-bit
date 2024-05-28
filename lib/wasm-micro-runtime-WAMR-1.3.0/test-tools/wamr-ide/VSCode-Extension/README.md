# Introduction

### An integrated development environment for WASM.

# How to debug this extension
> Note that when you download and
> decompress to get .vsix file from [our release](https://github.com/bytecodealliance/wasm-micro-runtime/releases).
> It's by default that the `source debugging` feature is not enabled.
> If you want to enable the `source debugging` feature of this extension,
> you could  download `lldb` from [our release](https://github.com/bytecodealliance/wasm-micro-runtime/releases)
> (This is the recommended way, and you could do it with a single click in VS Code).
> Then if you want to use your customized lldb patch,
> you could build your own version of `lldb`
> and then follow this [instruction](./resource/debug/README.md)
> to put them in the correct path

### 1. open `VSCode_Extension` directory with the `vscode`

```xml
File -> Open Folder -> select `VSCode_Extension`
```

### 2. run `npm install` in `terminal` to install necessary dependencies.

### 3. click `F5` or `ctrl+shift+D` switch to `Run and Debug` panel and click `Run Extension` to boot.

# Code Format

`prettier` is recommended and `.prettierrc.json` has been provided in workspace.
More details and usage guidance please refer [prettier](https://prettier.io/docs/en/install.html)

You can run following commands in current extension directory to check and apply
```shell
# install prettier firstly
npm install --save-dev prettier
# check format
npm run prettier-format-check
# apply
npm run prettier-format-apply
```