/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { readFromConfigFile, writeIntoConfigFile } from '../extension';
import { getUri } from '../utilities/getUri';

export class TargetConfigPanel {
    public static currentPanel: TargetConfigPanel | undefined;
    private readonly viewPanel: vscode.WebviewPanel;

    private _disposables: vscode.Disposable[] = [];
    public static buildArgs = {
        outputFileName: 'main.wasm',
        initMemorySize: '131072',
        maxMemorySize: '131072',
        stackSize: '4096',
        exportedSymbols: 'main',
        hostManagedHeapSize: '4096',
    };

    private static readonly userInputError: number = -2;
    private static readonly executionSuccess: number = 0;

    /**
     *
     * @param context extension context from extension.ts active func
     * @param panelName
     */
    constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this.viewPanel = panel;
        this.viewPanel.webview.html = this._getHtmlForWebview(
            this.viewPanel.webview,
            extensionUri,
            'resource/webview/page/configBuildTarget.html'
        );
        this.viewPanel.onDidDispose(this.dispose, null, this._disposables);
        this._setWebviewMessageListener(this.viewPanel.webview);
    }

    /**
     *
     * @param context
     */
    public static render(context: vscode.ExtensionContext): void {
        /* check if current panel is initialized */
        if (TargetConfigPanel.currentPanel) {
            TargetConfigPanel.currentPanel.viewPanel.reveal(
                vscode.ViewColumn.One
            );
        } else {
            const panel = vscode.window.createWebviewPanel(
                'targetConfig',
                'Config building target',
                vscode.ViewColumn.One,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true,
                }
            );

            TargetConfigPanel.currentPanel = new TargetConfigPanel(
                panel,
                context.extensionUri
            );
        }
    }

    private configBuildArgs(
        outputFileName: string,
        initMemSize: string,
        maxMemSize: string,
        stackSize: string,
        exportedSymbols: string,
        hostManagedHeapSize: string
    ): number {
        if (
            outputFileName === '' ||
            initMemSize === '' ||
            maxMemSize === '' ||
            stackSize === '' ||
            exportedSymbols === '' ||
            hostManagedHeapSize === ''
        ) {
            return TargetConfigPanel.userInputError;
        }

        let includePathArr = [];
        let excludeFileArr = [];

        const configObj = {
            outputFileName: outputFileName,
            initMemorySize: initMemSize,
            maxMemorySize: maxMemSize,
            stackSize: stackSize,
            exportedSymbols: exportedSymbols,
            hostManagedHeapSize: hostManagedHeapSize,
        };
        const configStr = readFromConfigFile();

        TargetConfigPanel.buildArgs = configObj;

        if (configStr !== '' && configStr !== undefined) {
            const configJson = JSON.parse(configStr);
            includePathArr =
                configJson['includePaths'] === undefined
                    ? []
                    : configJson['includePaths'];
            excludeFileArr =
                configJson['excludeFiles'] === undefined
                    ? []
                    : configJson['excludeFiles'];
        }

        writeIntoConfigFile(
            includePathArr,
            excludeFileArr,
            TargetConfigPanel.buildArgs
        );

        return TargetConfigPanel.executionSuccess;
    }

    private _getHtmlForWebview(
        webview: vscode.Webview,
        extensionUri: vscode.Uri,
        templatePath: string
    ) {
        /* get toolkit uri */
        const toolkitUri = getUri(webview, extensionUri, [
            'node_modules',
            '@vscode',
            'webview-ui-toolkit',
            'dist',
            'toolkit.js',
        ]);

        const styleUri = getUri(webview, extensionUri, [
            'resource',
            'webview',
            'css',
            'style.css',
        ]);

        const mainUri = getUri(webview, extensionUri, [
            'resource',
            'webview',
            'js',
            'configbuildtarget.js',
        ]);

        const resourcePath = path.join(extensionUri.fsPath, templatePath);
        let html = fs.readFileSync(resourcePath, 'utf-8');
        html = html
            .replace(/(\${toolkitUri})/, toolkitUri.toString())
            .replace(/(\${mainUri})/, mainUri.toString())
            .replace(/(\${styleUri})/, styleUri.toString())
            .replace(
                /(\${output_file_val})/,
                TargetConfigPanel.buildArgs.outputFileName
            )
            .replace(
                /(\${initial_mem_size_val})/,
                TargetConfigPanel.buildArgs.initMemorySize
            )
            .replace(
                /(\${max_mem_size_val})/,
                TargetConfigPanel.buildArgs.maxMemorySize
            )
            .replace(
                /(\${stack_size_val})/,
                TargetConfigPanel.buildArgs.stackSize
            )
            .replace(
                /(\${exported_symbols_val})/,
                TargetConfigPanel.buildArgs.exportedSymbols
            )
            .replace(
                /(\${host_managed_heap_size_val})/,
                TargetConfigPanel.buildArgs.hostManagedHeapSize
            );

        return html;
    }

    private _setWebviewMessageListener(webview: vscode.Webview) {
        webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'config_build_target':
                        if (
                            message.outputFileName === '' ||
                            message.initMemSize === '' ||
                            message.maxMemSize === '' ||
                            message.stackSize === '' ||
                            message.exportedSymbols === '' ||
                            message.hostManagedHeapSize === ''
                        ) {
                            vscode.window.showErrorMessage(
                                'Please fill chart before your submit!'
                            );
                            return;
                        } else if (
                            this.configBuildArgs(
                                message.outputFileName,
                                message.initMemSize,
                                message.maxMemSize,
                                message.stackSize,
                                message.exportedSymbols,
                                message.hostManagedHeapSize
                            ) === TargetConfigPanel.executionSuccess
                        ) {
                            vscode.window
                                .showInformationMessage(
                                    'Configurations have been saved!',
                                    'OK'
                                )
                                .then(() => {
                                    this.viewPanel.dispose();
                                    return;
                                });
                        }

                    default:
                        break;
                }
            },
            undefined,
            this._disposables
        );
    }

    private dispose() {
        TargetConfigPanel.currentPanel = undefined;
        this.viewPanel.dispose();

        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
