/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as os from 'os';

export class WasmDebugConfigurationProvider
    implements vscode.DebugConfigurationProvider {
    private wasmDebugConfig = {
        type: 'wamr-debug',
        name: 'Attach',
        request: 'attach',
        stopOnEntry: true,
        initCommands: os.platform() === 'win32' || os.platform() === 'darwin' ?
            /* linux and windows has different debug configuration */
            ['platform select remote-linux'] :
            undefined,
        attachCommands: [
            /* default port 1234 */
            'process connect -p wasm connect://127.0.0.1:1234',
        ]
    };

    public resolveDebugConfiguration(
        _: vscode.WorkspaceFolder | undefined,
        debugConfiguration: vscode.DebugConfiguration,
    ): vscode.ProviderResult<vscode.DebugConfiguration> {

        this.wasmDebugConfig = {
            ...this.wasmDebugConfig,
            ...debugConfiguration
        };

        return this.wasmDebugConfig;
    }

    public getDebugConfig(): vscode.DebugConfiguration {
        return this.wasmDebugConfig;
    }
}
