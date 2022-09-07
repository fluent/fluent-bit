/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { CreateDirectory, CopyFiles } from '../utilities/directoryUtilities';
import { getUri } from '../utilities/getUri';

export class NewProjectPanel {
    static USER_SET_WORKSPACE: string;
    public static currentPanel: NewProjectPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private _disposables: vscode.Disposable[] = [];

    static readonly USER_INTPUT_ERR: number = -2;
    static readonly DIR_EXSITED_ERR: number = -1;
    static readonly EXCUTION_SUCCESS: number = 0;

    /**
     * @param context extension context from extension.ts active func
     */
    constructor(extensionUri: vscode.Uri, panel: vscode.WebviewPanel) {
        this._panel = panel;
        this._panel.webview.html = this._getHtmlForWebview(
            this._panel.webview,
            extensionUri,
            'resource/webview/page/newProject.html'
        );
        this._setWebviewMessageListener(this._panel.webview, extensionUri);
        this._panel.onDidDispose(this.dispose, null, this._disposables);
    }

    /**
     * @param context
     */
    public static render(context: vscode.ExtensionContext) {
        NewProjectPanel.USER_SET_WORKSPACE = vscode.workspace
            .getConfiguration()
            .get('WAMR-IDE.configWorkspace') as string;

        /* check if current panel is initialized */
        if (NewProjectPanel.currentPanel) {
            NewProjectPanel.currentPanel._panel.reveal(vscode.ViewColumn.One);
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

            /* create new project panel obj */
            NewProjectPanel.currentPanel = new NewProjectPanel(
                context.extensionUri,
                panel
            );
        }
    }

    /**
     * @param projName project name input by user
     * @param template
     */
    private _creatNewProject(
        projName: string,
        template: string,
        extensionUri: vscode.Uri
    ): number {
        if (projName === '' || template === '') {
            return NewProjectPanel.USER_INTPUT_ERR;
        }

        let ROOT_PATH = path.join(NewProjectPanel.USER_SET_WORKSPACE, projName);
        let EXT_PATH = extensionUri.fsPath;

        /* if the direcotry has exsited, then ignore the creation and return */
        if (fs.existsSync(ROOT_PATH)) {
            if (fs.lstatSync(ROOT_PATH).isDirectory()) {
                return NewProjectPanel.DIR_EXSITED_ERR;
            }
        }

        /* create necessary floders under the project directory */
        CreateDirectory(path.join(ROOT_PATH, '.wamr'));
        CreateDirectory(path.join(ROOT_PATH, 'include'));
        CreateDirectory(path.join(ROOT_PATH, 'src'));

        /* copy scripts files to project_root_path/.wamr */
        CopyFiles(
            path.join(EXT_PATH, 'resource/scripts/CMakeLists.txt'),
            path.join(ROOT_PATH, '.wamr/CMakeLists.txt')
        );

        CopyFiles(
            path.join(EXT_PATH, 'resource/scripts/project.cmake'),
            path.join(ROOT_PATH, '.wamr/project.cmake')
        );

        return NewProjectPanel.EXCUTION_SUCCESS;
    }

    public _getHtmlForWebview(
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
        // Handle messages from the webview
        webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'create_new_project':
                        if (
                            this._creatNewProject(
                                message.projectName,
                                message.template,
                                extensionUri
                            ) === NewProjectPanel.EXCUTION_SUCCESS
                        ) {
                            /* post message to page to inform the project creation has finished */
                            webview.postMessage({
                                command: 'proj_creation_finish',
                                prjName: message.projectName,
                            });
                        } else if (
                            this._creatNewProject(
                                message.projectName,
                                message.template,
                                extensionUri
                            ) === NewProjectPanel.DIR_EXSITED_ERR
                        ) {
                            vscode.window.showErrorMessage(
                                'Project : ' +
                                    message.projectName +
                                    ' exsits in your current root path, please change project name or root path!'
                            );
                            return;
                        } else if (
                            this._creatNewProject(
                                message.projectName,
                                message.template,
                                extensionUri
                            ) === NewProjectPanel.USER_INTPUT_ERR
                        ) {
                            vscode.window.showErrorMessage(
                                'Please fill chart before your submit!'
                            );
                            return;
                        }
                        return;

                    case 'open_project':
                        vscode.window.showInformationMessage(
                            'Project : ' +
                                message.projectName +
                                ' will be opened!'
                        );
                        let isWorkspaceEmpty: boolean;

                        let projPath = path.join(
                            NewProjectPanel.USER_SET_WORKSPACE,
                            message.projectName
                        );
                        let uri = vscode.Uri.file(projPath);

                        /**
                         * check if the vscode workspace folder is empty,
                         * if yes, open new window, else open in current window
                         */
                        isWorkspaceEmpty = !vscode.workspace
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
                        this._panel.dispose();
                        return;

                    default:
                        break;
                }
            },
            undefined,
            this._disposables
        );
    }

    private dispose() {
        NewProjectPanel.currentPanel = undefined;
        this._panel.dispose();

        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
