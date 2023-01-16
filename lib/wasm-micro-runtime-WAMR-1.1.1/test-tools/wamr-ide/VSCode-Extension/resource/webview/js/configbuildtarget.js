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
    let initmemSize = document.getElementById('initial_mem_size').value;
    let maxmemSize = document.getElementById('max_mem_size').value;
    let stackSize = document.getElementById('stack_size').value;
    let exportedSymbols = document.getElementById('exported_symbols').value;

    vscode.postMessage({
        command: 'config_build_target',
        outputFileName: outputFileName,
        initmemSize: initmemSize,
        maxmemSize: maxmemSize,
        stackSize: stackSize,
        exportedSymbols: exportedSymbols,
    });
}
