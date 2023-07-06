/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import { readFromFile } from './utilities/directoryUtilities';
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
    private eventEmitter: vscode.EventEmitter<vscode.Uri | vscode.Uri[]>;

    constructor() {
        this.eventEmitter = new vscode.EventEmitter();
        this.onDidChangeFileDecorations = this.eventEmitter.event;
        this.disposables.push(
            vscode.window.registerFileDecorationProvider(this)
        );
    }

    public provideFileDecoration(
        uri: vscode.Uri
    ): vscode.ProviderResult<vscode.FileDecoration> {
        const currentPrjDir =
            os.platform() === 'win32'
                ? (vscode.workspace.workspaceFolders?.[0].uri.fsPath as string)
                : os.platform() === 'linux' || os.platform() === 'darwin'
                ? (vscode.workspace.workspaceFolders?.[0].uri.path as string)
                : '';

        const pathRelative = (uri.fsPath ? uri.fsPath : uri.toString()).replace(
            currentPrjDir,
            '..'
        );

        const prjConfigDir = path.join(currentPrjDir, '.wamr');
        const configFilePath = path.join(
            prjConfigDir,
            'compilation_config.json'
        );
        if (readFromFile(configFilePath) !== '') {
            const configData = JSON.parse(readFromFile(configFilePath));
            const includePathArr = configData['includePaths'];
            const excludeFileArr = configData['excludeFiles'];

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
        this.eventEmitter.fire(uri);
    }
}

export const decorationProvider: DecorationProvider = new DecorationProvider();
