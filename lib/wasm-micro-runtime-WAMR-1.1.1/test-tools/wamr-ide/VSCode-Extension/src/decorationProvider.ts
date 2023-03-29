/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import { ReadFromFile } from './utilities/directoryUtilities';
import * as path from 'path';
import * as os from 'os';

const DECORATION_INCLUDE_PATHS: vscode.FileDecoration =
    new vscode.FileDecoration(
        '✔',
        'Included',
        new vscode.ThemeColor('list.highlightForeground')
    );
const DECORATION_EXCLUDE_FILES: vscode.FileDecoration =
    new vscode.FileDecoration(
        '✗',
        'Excluded',
        new vscode.ThemeColor('list.errorForeground')
    );

export class DecorationProvider implements vscode.FileDecorationProvider {
    private disposables: vscode.Disposable[] = [];
    public onDidChangeFileDecorations: vscode.Event<
        vscode.Uri | vscode.Uri[] | undefined
    >;
    private _eventEmiter: vscode.EventEmitter<vscode.Uri | vscode.Uri[]>;

    constructor() {
        this._eventEmiter = new vscode.EventEmitter();
        this.onDidChangeFileDecorations = this._eventEmiter.event;
        this.disposables.push(
            vscode.window.registerFileDecorationProvider(this)
        );
    }

    public provideFileDecoration(
        uri: vscode.Uri
    ): vscode.ProviderResult<vscode.FileDecoration> {
        let currentPrjDir,
            prjConfigDir,
            configFilePath,
            configData,
            includePathArr = new Array(),
            excludeFileArr = new Array(),
            pathRelative;

        /* Read include_paths and exclude_fils from the config file */
        currentPrjDir =
            os.platform() === 'win32'
                ? (vscode.workspace.workspaceFolders?.[0].uri.fsPath as string)
                : os.platform() === 'linux' || os.platform() === 'darwin'
                ? (currentPrjDir = vscode.workspace.workspaceFolders?.[0].uri
                      .path as string)
                : '';

        pathRelative = (uri.fsPath ? uri.fsPath : uri.toString()).replace(
            currentPrjDir,
            '..'
        );

        prjConfigDir = path.join(currentPrjDir, '.wamr');
        configFilePath = path.join(prjConfigDir, 'compilation_config.json');
        if (ReadFromFile(configFilePath) !== '') {
            configData = JSON.parse(ReadFromFile(configFilePath));
            includePathArr = configData['include_paths'];
            excludeFileArr = configData['exclude_files'];

            if (includePathArr.indexOf(pathRelative) > -1) {
                return DECORATION_INCLUDE_PATHS;
            } else if (excludeFileArr.indexOf(pathRelative) > -1) {
                return DECORATION_EXCLUDE_FILES;
            }
        }
    }

    public dispose(): void {
        this.disposables.forEach(d => d.dispose());
    }

    public updateDecorationsForSource(uri: vscode.Uri): void {
        this._eventEmiter.fire(uri);
    }
}

export const decorationProvider: DecorationProvider = new DecorationProvider();
