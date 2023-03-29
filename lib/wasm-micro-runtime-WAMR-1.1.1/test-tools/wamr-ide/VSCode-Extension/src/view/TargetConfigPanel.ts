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
    private readonly _panel: vscode.WebviewPanel;

    private _disposables: vscode.Disposable[] = [];
    public static BUILD_ARGS = {
        output_file_name: 'main.wasm',
        init_memory_size: '131072',
        max_memory_size: '131072',
        stack_size: '4096',
        exported_symbols: 'main',
    };

    static readonly USER_INTPUT_ERR: number = -2;
    static readonly EXCUTION_SUCCESS: number = 0;

    /**
     *
     * @param context extension context from extension.ts active func
     * @param panelName
     */
    constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this._panel = panel;
        this._panel.webview.html = this._getHtmlForWebview(
            this._panel.webview,
            extensionUri,
            'resource/webview/page/configBuildTarget.html'
        );
        this._panel.onDidDispose(this.dispose, null, this._disposables);
        this._setWebviewMessageListener(this._panel.webview);
    }

    /**
     *
     * @param context
     */
    public static render(context: vscode.ExtensionContext) {
        /* check if current panel is initialized */
        if (TargetConfigPanel.currentPanel) {
            TargetConfigPanel.currentPanel._panel.reveal(vscode.ViewColumn.One);
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

    private _configBuildArgs(
        outputFileName: string,
        initmemSize: string,
        maxmemSize: string,
        stackSize: string,
        exportedSymbols: string
    ): number {
        if (
            outputFileName === '' ||
            initmemSize === '' ||
            maxmemSize === '' ||
            stackSize === '' ||
            exportedSymbols === ''
        ) {
            return TargetConfigPanel.USER_INTPUT_ERR;
        }

        let _configStr: string;
        let includePathArr = new Array();
        let excludeFileArr = new Array();
        let configJson: any;

        let _configObj = {
            output_file_name: outputFileName,
            init_memory_size: initmemSize,
            max_memory_size: maxmemSize,
            stack_size: stackSize,
            exported_symbols: exportedSymbols,
        };

        TargetConfigPanel.BUILD_ARGS = _configObj;

        _configStr = readFromConfigFile();

        if (_configStr !== '' && _configStr !== undefined) {
            configJson = JSON.parse(_configStr);
            includePathArr =
                configJson['include_paths'] === undefined
                    ? []
                    : configJson['include_paths'];
            excludeFileArr =
                configJson['exclude_files'] === undefined
                    ? []
                    : configJson['exclude_files'];
        }

        writeIntoConfigFile(
            includePathArr,
            excludeFileArr,
            TargetConfigPanel.BUILD_ARGS
        );

        return TargetConfigPanel.EXCUTION_SUCCESS;
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
                TargetConfigPanel.BUILD_ARGS.output_file_name
            )
            .replace(
                /(\${initial_mem_size_val})/,
                TargetConfigPanel.BUILD_ARGS.init_memory_size
            )
            .replace(
                /(\${max_mem_size_val})/,
                TargetConfigPanel.BUILD_ARGS.max_memory_size
            )
            .replace(
                /(\${stack_size_val})/,
                TargetConfigPanel.BUILD_ARGS.stack_size
            )
            .replace(
                /(\${exported_symbols_val})/,
                TargetConfigPanel.BUILD_ARGS.exported_symbols
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
                            message.initmemSize === '' ||
                            message.maxmemSize === '' ||
                            message.stackSize === '' ||
                            message.exportedSymbols === ''
                        ) {
                            vscode.window.showErrorMessage(
                                'Please fill chart before your submit!'
                            );
                            return;
                        } else if (
                            this._configBuildArgs(
                                message.outputFileName,
                                message.initmemSize,
                                message.maxmemSize,
                                message.stackSize,
                                message.exportedSymbols
                            ) === TargetConfigPanel.EXCUTION_SUCCESS
                        ) {
                            vscode.window
                                .showInformationMessage(
                                    'Configurations have been saved!',
                                    'OK'
                                )
                                .then(() => {
                                    this._panel.dispose();
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
        this._panel.dispose();

        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
