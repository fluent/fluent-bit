/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

const vscode = acquireVsCodeApi();

document.getElementById('btn_submit').onclick = () => {
    submitFunc();
};

function submitFunc() {
    let outputFileName = document.getElementById('output_file_name').value;
    let initMemSize = document.getElementById('initial_mem_size').value;
    let maxMemSize = document.getElementById('max_mem_size').value;
    let stackSize = document.getElementById('stack_size').value;
    let exportedSymbols = document.getElementById('exported_symbols').value;
    let hostManagedHeapSize = document.getElementById('host_managed_heap_size').value;

    vscode.postMessage({
        command: 'config_build_target',
        outputFileName: outputFileName,
        initMemSize: initMemSize,
        maxMemSize: maxMemSize,
        stackSize: stackSize,
        exportedSymbols: exportedSymbols,
        hostManagedHeapSize: hostManagedHeapSize,
    });
}
