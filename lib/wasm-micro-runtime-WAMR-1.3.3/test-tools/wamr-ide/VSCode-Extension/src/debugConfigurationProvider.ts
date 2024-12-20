/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as os from 'os';

/* see https://github.com/llvm/llvm-project/tree/main/lldb/tools/lldb-vscode#attaching-settings */
export interface WasmDebugConfig {
    type: string;
    name: string;
    request: string;
    program?: string;
    pid?: string;
    stopOnEntry?: boolean;
    waitFor?: boolean;
    initCommands?: string[];
    preRunCommands?: string[];
    stopCommands?: string[];
    exitCommands?: string[];
    terminateCommands?: string[];
    attachCommands?: string[];
}

export class WasmDebugConfigurationProvider
    implements vscode.DebugConfigurationProvider
{
    private wasmDebugConfig: WasmDebugConfig = {
        type: 'wamr-debug',
        name: 'Attach',
        request: 'attach',
        stopOnEntry: true,
        attachCommands: [
            /* default port 1234 */
            'process connect -p wasm connect://127.0.0.1:1234',
        ],
    };

    constructor(extensionPath: string) {
        this.wasmDebugConfig.initCommands = [
            /* Add rust formatters -> https://lldb.llvm.org/use/variable.html */
            `command script import ${extensionPath}/formatters/rust.py`,
        ];

        if (os.platform() === 'win32' || os.platform() === 'darwin') {
            this.wasmDebugConfig.initCommands.push(
                'platform select remote-linux'
            );
        }
    }

    public resolveDebugConfiguration(
        _: vscode.WorkspaceFolder | undefined,
        debugConfiguration: vscode.DebugConfiguration
    ): vscode.ProviderResult<vscode.DebugConfiguration> {
        this.wasmDebugConfig = {
            ...this.wasmDebugConfig,
            ...debugConfiguration,
        };

        return this.wasmDebugConfig;
    }

    public getDebugConfig(): vscode.DebugConfiguration {
        return this.wasmDebugConfig;
    }
}
