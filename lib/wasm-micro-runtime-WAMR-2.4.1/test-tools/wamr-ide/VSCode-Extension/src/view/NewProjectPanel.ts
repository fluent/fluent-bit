/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import {
    createDirectory,
    copyFiles,
    checkFolderName,
} from '../utilities/directoryUtilities';
import { getUri } from '../utilities/getUri';

export class NewProjectPanel {
    public static userSetWorkSpace: string;
    public static currentPanel: NewProjectPanel | undefined;
    private readonly viewPanel: vscode.WebviewPanel;
    private disposableArr: vscode.Disposable[] = [];

    private static readonly executionSuccess = 0;
    private static readonly dirExistedError = -1;
    private static readonly userInputError = -2;
    private static readonly dirPathInvalidError = -3;

    constructor(extensionUri: vscode.Uri, panel: vscode.WebviewPanel) {
        this.viewPanel = panel;
        this.viewPanel.webview.html = this.getHtmlForWebview(
            this.viewPanel.webview,
            extensionUri,
            'resource/webview/page/newProject.html'
        );
        this._setWebviewMessageListener(this.viewPanel.webview, extensionUri);
        this.viewPanel.onDidDispose(this.dispose, null, this.disposableArr);
    }

    public static render(context: vscode.ExtensionContext): void {
        NewProjectPanel.userSetWorkSpace = vscode.workspace
            .getConfiguration()
            .get('WAMR-IDE.configWorkspace') as string;

        /* check if current panel is initialized */
        if (NewProjectPanel.currentPanel) {
            NewProjectPanel.currentPanel.viewPanel.reveal(
                vscode.ViewColumn.One
            );
        } else {
            const panel = vscode.window.createWebviewPanel(
                'newProject',
                'Create project',
                vscode.ViewColumn.One,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true,
                }
            );

            NewProjectPanel.currentPanel = new NewProjectPanel(
                context.extensionUri,
                panel
            );
        }
    }

    private createNewProject(
        projName: string,
        template: string,
        extensionUri: vscode.Uri
    ): number {
        if (projName === '' || template === '') {
            return NewProjectPanel.userInputError;
        }

        if (!checkFolderName(projName)) {
            return NewProjectPanel.dirPathInvalidError;
        }

        const ROOT_PATH = path.join(NewProjectPanel.userSetWorkSpace, projName);
        const EXT_PATH = extensionUri.fsPath;

        if (fs.existsSync(ROOT_PATH)) {
            if (fs.lstatSync(ROOT_PATH).isDirectory()) {
                return NewProjectPanel.dirExistedError;
            }
        }

        createDirectory(path.join(ROOT_PATH, '.wamr'));
        createDirectory(path.join(ROOT_PATH, 'include'));
        createDirectory(path.join(ROOT_PATH, 'src'));

        copyFiles(
            path.join(EXT_PATH, 'resource/scripts/CMakeLists.txt'),
            path.join(ROOT_PATH, '.wamr/CMakeLists.txt')
        );

        copyFiles(
            path.join(EXT_PATH, 'resource/scripts/project.cmake'),
            path.join(ROOT_PATH, '.wamr/project.cmake')
        );

        return NewProjectPanel.executionSuccess;
    }

    public getHtmlForWebview(
        webview: vscode.Webview,
        extensionUri: vscode.Uri,
        templatePath: string
    ): string {
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
            'newproj.js',
        ]);

        const resourcePath = path.join(extensionUri.fsPath, templatePath);
        let html = fs.readFileSync(resourcePath, 'utf-8');
        html = html
            .replace(/(\${toolkitUri})/, toolkitUri.toString())
            .replace(/(\${mainUri})/, mainUri.toString())
            .replace(/(\${styleUri})/, styleUri.toString());

        return html;
    }

    private _setWebviewMessageListener(
        webview: vscode.Webview,
        extensionUri: vscode.Uri
    ) {
        webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'create_new_project':
                        const createNewProjectStatus = this.createNewProject(
                            message.projectName,
                            message.template,
                            extensionUri
                        );
                        if (
                            createNewProjectStatus ===
                            NewProjectPanel.executionSuccess
                        ) {
                            webview.postMessage({
                                command: 'proj_creation_finish',
                                prjName: message.projectName,
                            });
                        } else if (
                            createNewProjectStatus ===
                            NewProjectPanel.dirExistedError
                        ) {
                            vscode.window.showErrorMessage(
                                'Project : ' +
                                    message.projectName +
                                    ' exists in your current root path, please change project name or root path!'
                            );
                            return;
                        } else if (
                            createNewProjectStatus ===
                            NewProjectPanel.userInputError
                        ) {
                            vscode.window.showErrorMessage(
                                'Please fill chart before your submit!'
                            );
                            return;
                        } else if (
                            createNewProjectStatus ===
                            NewProjectPanel.dirPathInvalidError
                        ) {
                            if (os.platform() === 'win32') {
                                vscode.window.showErrorMessage(
                                    "A file name can't contain any of the following characters: ' / \\ : * ? < > | ' and the length should be less than 255"
                                );
                            } else if (
                                os.platform() === 'linux' ||
                                os.platform() === 'darwin'
                            ) {
                                vscode.window.showErrorMessage(
                                    "A file name can't contain following characters: '/' and the length should be less than 255"
                                );
                            }
                            return;
                        }
                        return;

                    case 'open_project':
                        vscode.window.showInformationMessage(
                            'Project : ' +
                                message.projectName +
                                ' will be opened!'
                        );

                        const projPath = path.join(
                            NewProjectPanel.userSetWorkSpace,
                            message.projectName
                        );
                        const uri = vscode.Uri.file(projPath);

                        /**
                         * check if the vscode workspace folder is empty,
                         * if yes, open new window, else open in current window
                         */
                        const isWorkspaceEmpty = !vscode.workspace
                            .workspaceFolders?.[0]
                            ? true
                            : false;
                        isWorkspaceEmpty === false
                            ? vscode.commands.executeCommand(
                                  'vscode.openFolder',
                                  uri,
                                  {
                                      forceNewWindow: true,
                                  }
                              )
                            : vscode.commands.executeCommand(
                                  'vscode.openFolder',
                                  uri
                              );

                    case 'close_webview':
                        this.viewPanel.dispose();
                        return;

                    default:
                        break;
                }
            },
            undefined,
            this.disposableArr
        );
    }

    private dispose() {
        NewProjectPanel.currentPanel = undefined;
        this.viewPanel.dispose();

        while (this.disposableArr.length) {
            const disposable = this.disposableArr.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
