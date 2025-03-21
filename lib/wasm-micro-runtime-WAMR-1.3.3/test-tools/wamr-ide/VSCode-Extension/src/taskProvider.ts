/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as os from 'os';
import { TargetConfigPanel } from './view/TargetConfigPanel';

export interface OwnShellOption {
    cmd: string;
    options: vscode.ShellExecutionOptions;
}

export class WasmTaskProvider implements vscode.TaskProvider {
    constructor(
        public _type: Map<string, string>,
        public _script: Map<string, string>,
        public _wamrVersion: string
    ) {}

    buildShellOption: OwnShellOption | undefined;
    runShellOption: OwnShellOption | undefined;
    debugShellOption: OwnShellOption | undefined;
    destroyShellOption: OwnShellOption | undefined;

    private wasmPromise: Thenable<vscode.Task[]> | undefined = undefined;

    public provideTasks(): Thenable<vscode.Task[]> | undefined {
        if (!this.wasmPromise) {
            /* target name is used for generated aot target */
            const targetName =
                TargetConfigPanel.buildArgs.outputFileName.split('.')[0];
            const heapSize = TargetConfigPanel.buildArgs.hostManagedHeapSize;

            if (
                os.platform() === 'linux' ||
                os.platform() === 'darwin' ||
                os.platform() === 'win32'
            ) {
                /* build */
                this.buildShellOption = {
                    cmd:
                        os.platform() === 'linux' || os.platform() === 'darwin'
                            ? 'bash'
                            : (this._script.get('buildScript') as string),
                    options: {
                        executable: this._script.get('buildScript'),
                        shellArgs: [targetName, this._wamrVersion],
                    },
                };

                /* debug */
                this.debugShellOption = {
                    cmd:
                        os.platform() === 'linux' || os.platform() === 'darwin'
                            ? 'bash'
                            : (this._script.get('debugScript') as string),
                    options: {
                        executable: this._script.get('debugScript'),
                        shellArgs: [targetName, this._wamrVersion, heapSize],
                    },
                };

                /* run */
                this.runShellOption = {
                    cmd:
                        os.platform() === 'linux' || os.platform() === 'darwin'
                            ? 'bash'
                            : (this._script.get('runScript') as string),
                    options: {
                        executable: this._script.get('runScript'),
                        shellArgs: [targetName, this._wamrVersion, heapSize],
                    },
                };

                /* destroy */
                /* run */
                this.destroyShellOption = {
                    cmd:
                        os.platform() === 'linux' || os.platform() === 'darwin'
                            ? 'bash'
                            : (this._script.get('destroyScript') as string),
                    options: {
                        executable: this._script.get('destroyScript'),
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

                this.destroyShellOption = {
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

                new vscode.Task(
                    { type: 'wasm' },
                    vscode.TaskScope.Workspace,
                    'Wasm-Container-Before-Build',
                    this._type.get('Destroy') as string,
                    new vscode.ShellExecution(
                        this.destroyShellOption.cmd,
                        this.destroyShellOption.options
                    )
                ),

                new vscode.Task(
                    { type: 'wasm' },
                    vscode.TaskScope.Workspace,
                    'Wasm-Container-Before-Debug',
                    this._type.get('Destroy') as string,
                    new vscode.ShellExecution(
                        this.destroyShellOption.cmd,
                        this.destroyShellOption.options
                    )
                ),

                new vscode.Task(
                    { type: 'wasm' },
                    vscode.TaskScope.Workspace,
                    'Wasm-Container-Before-Run',
                    this._type.get('Destroy') as string,
                    new vscode.ShellExecution(
                        this.destroyShellOption.cmd,
                        this.destroyShellOption.options
                    )
                ),

                new vscode.Task(
                    { type: 'wasm' },
                    vscode.TaskScope.Workspace,
                    'Wasm-Container-After-Build',
                    this._type.get('Destroy') as string,
                    new vscode.ShellExecution(
                        this.destroyShellOption.cmd,
                        this.destroyShellOption.options
                    )
                ),

                new vscode.Task(
                    { type: 'wasm' },
                    vscode.TaskScope.Workspace,
                    'Wasm-Container-After-Debug',
                    this._type.get('Destroy') as string,
                    new vscode.ShellExecution(
                        this.destroyShellOption.cmd,
                        this.destroyShellOption.options
                    )
                ),

                new vscode.Task(
                    { type: 'wasm' },
                    vscode.TaskScope.Workspace,
                    'Wasm-Container-After-Run',
                    this._type.get('Destroy') as string,
                    new vscode.ShellExecution(
                        this.destroyShellOption.cmd,
                        this.destroyShellOption.options
                    )
                ),
            ]);
        }

        return this.wasmPromise;
    }

    /**
     * if the task or task in tasks.json does not set command, `
     * resolveTask` will be invoked,
     * otherwise, `provideTasks` will be invoked
     * @param _task
     * @returns
     */
    public resolveTask(task: vscode.Task): vscode.Task | undefined {
        if (task) {
            return task;
        }
        return undefined;
    }
}
