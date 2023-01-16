/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as os from 'os';

export class WasmDebugConfigurationProvider
    implements vscode.DebugConfigurationProvider
{
    constructor() {}

    /* default port set as 1234 */
    private port = 1234;
    private hostPath!: string;
    private providerPromise: Thenable<vscode.DebugConfiguration> | undefined =
        undefined;

    private wasmDebugConfig!: vscode.DebugConfiguration;

    public resolveDebugConfiguration():
        | Thenable<vscode.DebugConfiguration>
        | undefined {
        if (!this.providerPromise) {
            this.providerPromise = Promise.resolve(this.wasmDebugConfig);
            return this.providerPromise;
        }
        return this.providerPromise;
    }

    public setDebugConfig(hostPath: string, port: number) {
        this.port = port;
        this.hostPath = hostPath;
        /* linux and windows has different debug configuration */
        if (os.platform() === 'win32' || os.platform() === 'darwin') {
            this.wasmDebugConfig = {
                type: 'wamr-debug',
                name: 'Attach',
                request: 'attach',
                ['stopOnEntry']: true,
                ['initCommands']: ['platform select remote-linux'],
                ['attachCommands']: [
                    'process connect -p wasm connect://127.0.0.1:' + port + '',
                ],
            };
        } else if (os.platform() === 'linux') {
            this.wasmDebugConfig = {
                type: 'wamr-debug',
                name: 'Attach',
                request: 'attach',
                ['stopOnEntry']: true,
                ['attachCommands']: [
                    'process connect -p wasm connect://127.0.0.1:' + port + '',
                ],
            };
        }
    }

    public getDebugConfig() {
        return this.wasmDebugConfig;
    }
}
