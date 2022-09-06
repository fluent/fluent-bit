/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as os from 'os';
import { TargetConfigPanel } from './view/TargetConfigPanel';

interface WasmTaskDefinition extends vscode.TaskDefinition {
    /**
     * The build flavor.
     */
    flavor: string;
}

export interface OwnShellOption {
    cmd: string;
    options: vscode.ShellExecutionOptions;
}

export class WasmTaskProvider implements vscode.TaskProvider {
    constructor(
        public _type: Map<string, string>,
        public _script: Map<string, string>
    ) {}

    buildShellOption: OwnShellOption | undefined;
    runShellOption: OwnShellOption | undefined;
    debugShellOption: OwnShellOption | undefined;

    private wasmPromise: Thenable<vscode.Task[]> | undefined = undefined;

    public provideTasks(): Thenable<vscode.Task[]> | undefined {
        let targetName =
            TargetConfigPanel.BUILD_ARGS.output_file_name.split('.')[0];

        if (os.platform() === 'linux') {
            /* build */
            this.buildShellOption = {
                cmd: 'bash',
                options: {
                    executable: this._script.get('buildScript'),
                    shellArgs: [targetName],
                },
            };

            /* debug */
            this.debugShellOption = {
                cmd: 'bash',
                options: {
                    executable: this._script.get('debugScript'),
                    shellArgs: [targetName],
                },
            };

            /* run */
            this.runShellOption = {
                cmd: 'bash',
                options: {
                    executable: this._script.get('runScript'),
                    shellArgs: [targetName],
                },
            };
        } else if (os.platform() === 'win32') {
            this.buildShellOption = {
                cmd: this._script.get('buildScript') as string,
                options: {
                    executable: this._script.get('buildScript'),
                    shellArgs: [targetName],
                },
            };
            /* debug */
            this.debugShellOption = {
                cmd: this._script.get('debugScript') as string,
                options: {
                    executable: this._script.get('debugScript'),
                    shellArgs: [targetName],
                },
            };
            /* run */
            this.runShellOption = {
                cmd: this._script.get('runScript') as string,
                options: {
                    executable: this._script.get('runScript'),
                    shellArgs: [targetName],
                },
            };
        } else {
            this.buildShellOption = {
                cmd: "echo 'os platform is not supported yet'",
                options: {},
            };

            this.debugShellOption = {
                cmd: "echo 'os platform is not supported yet'",
                options: {},
            };

            this.runShellOption = {
                cmd: "echo 'os platform is not supported yet'",
                options: {},
            };
        }

        this.wasmPromise = Promise.resolve([
            new vscode.Task(
                { type: 'wasm' },
                vscode.TaskScope.Workspace,
                'Wasm',
                this._type.get('Build') as string,
                new vscode.ShellExecution(
                    this.buildShellOption.cmd,
                    this.buildShellOption.options
                )
            ),

            new vscode.Task(
                { type: 'wasm' },
                vscode.TaskScope.Workspace,
                'Wasm',
                this._type.get('Run') as string,
                new vscode.ShellExecution(
                    this.runShellOption.cmd,
                    this.runShellOption.options
                )
            ),

            new vscode.Task(
                { type: 'wasm' },
                vscode.TaskScope.Workspace,
                'Wasm',
                this._type.get('Debug') as string,
                new vscode.ShellExecution(
                    this.debugShellOption.cmd,
                    this.debugShellOption.options
                )
            ),
        ]);
        return this.wasmPromise;
    }

    /**
     * if the task or task in tasks.json does not set command, `
     * resolveTask` will be invoked,
     * otherwise, `provideTasks` will be invoked
     * @param _task
     * @returns
     */
    public resolveTask(_task: vscode.Task): vscode.Task | undefined {
        return undefined;
    }
}
