# Introduction

### An integrated development environment for WASM.

# How to debug this extension

> Note that please build `lldb` firstly follow this
> [instruction](./resource/debug/README.md) if you want to enable
> `source debugging` feature of this extension

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