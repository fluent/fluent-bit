### If you want to enable `source debugging` for this extension and use your own patched `lldb`, please build `lldb` firstly following this [instruction](../../../../../doc/source_debugging.md#debugging-with-interpreter)

### After building(`linux` for example), create `bin` folder and `lib` folder respectively in `linux` directory, add following necessary target files into the folders

```shell
/llvm/build-lldb/bin/lldb # move this file to {VS Code directory}/resource/debug/linux/bin/
/llvm/build-lldb/bin/lldb-vscode # move this file to {VS Code directory}/resource/debug/linux/bin/
/llvm/build-lldb/lib/liblldb.so.13 # move this file to {VS Code directory}/resource/debug/linux/lib/
```

> If you are debugging this extension following this [tutorial](../../README.md), {VS Code directory} will be `{WAMR root directory}/test-tools/wamr-ide/VSCode-Extension`. If you want to replace the current lldb with your own patched version so that you can use your patched lldb in VS Code, {VS Code directory} will be `~/.vscode/extensions/wamr.wamride-1.1.2` or `~/.vscode-server/extensions/wamr.wamride-1.1.2`.

Note: For macOS, the library is named like `liblldb.13.0.1.dylib`.

### Then you can start the extension and run the execute source debugging by clicking the `debug` button in the extension panel.
