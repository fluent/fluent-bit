/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as fileSystem from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';

import { WasmTaskProvider } from './taskProvider';
import { TargetConfigPanel } from './view/TargetConfigPanel';
import { NewProjectPanel } from './view/NewProjectPanel';
import {
    checkIfDirectoryExists,
    writeIntoFile,
    readFromFile,
} from './utilities/directoryUtilities';
import { decorationProvider } from './decorationProvider';
import { WasmDebugConfigurationProvider } from './debugConfigurationProvider';
import {
    isLLDBInstalled,
    promptInstallLLDB,
    getWAMRExtensionVersion,
} from './utilities/lldbUtilities';

import {
    checkIfDockerStarted,
    checkIfDockerImagesExist,
    promptSetupDockerImages,
} from './utilities/dockerUtilities';
import { SelectionOfPrompt } from './constants';

let wasmTaskProvider: WasmTaskProvider;
let wasmDebugConfigProvider: WasmDebugConfigurationProvider;
let currentPrjDir = '';
let isWasmProject = false;

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export async function activate(context: vscode.ExtensionContext) {
    const extensionPath = context.extensionPath;
    const osPlatform = os.platform();
    const wamrVersion = getWAMRExtensionVersion(context.extensionPath);
    const typeMap = new Map<string, string>();
    const scriptMap = new Map<string, string>();
    /* set relative path of build.bat|sh script */
    const scriptPrefix = 'resource/scripts/';

    let buildScript = '',
        runScript = '',
        debugScript = '',
        destroyScript = '',
        buildScriptFullPath = '',
        runScriptFullPath = '',
        debugScriptFullPath = '',
        destroyScriptFullPath = '',
        /* include paths array used for written into config file */
        includePathArr = new Array<string>(),
        /* exclude files array used for written into config file */
        excludeFileArr = new Array<string>();

    /**
     * Provide Build & Run Task with Task Provider instead of "tasks.json"
     */

    if (osPlatform === 'win32') {
        buildScript = scriptPrefix.concat('build.bat');
        runScript = scriptPrefix.concat('run.bat');
        debugScript = scriptPrefix.concat('boot_debugger_server.bat');
        destroyScript = scriptPrefix.concat('destroy.bat');
    } else if (osPlatform === 'linux' || osPlatform === 'darwin') {
        buildScript = scriptPrefix.concat('build.sh');
        runScript = scriptPrefix.concat('run.sh');
        debugScript = scriptPrefix.concat('boot_debugger_server.sh');
        destroyScript = scriptPrefix.concat('destroy.sh');
    }

    buildScriptFullPath = path.join(extensionPath, buildScript);
    runScriptFullPath = path.join(extensionPath, runScript);
    debugScriptFullPath = path.join(extensionPath, debugScript);
    destroyScriptFullPath = path.join(extensionPath, destroyScript);

    scriptMap.set('buildScript', buildScriptFullPath);
    scriptMap.set('runScript', runScriptFullPath);
    scriptMap.set('debugScript', debugScriptFullPath);
    scriptMap.set('destroyScript', destroyScriptFullPath);

    typeMap.set('Build', 'Build');
    typeMap.set('Run', 'Run');
    typeMap.set('Debug', 'Debug');
    typeMap.set('Destroy', 'Destroy');

    wasmTaskProvider = new WasmTaskProvider(typeMap, scriptMap, wamrVersion);

    vscode.tasks.registerTaskProvider('wasm', wasmTaskProvider);

    if (vscode.workspace.workspaceFolders?.[0]) {
        if (osPlatform === 'win32') {
            currentPrjDir = vscode.workspace.workspaceFolders?.[0].uri
                .fsPath as string;
        } else if (osPlatform === 'linux' || osPlatform === 'darwin') {
            currentPrjDir = vscode.workspace.workspaceFolders?.[0].uri
                .path as string;
        }

        /**
         * check whether current project opened in vscode workspace is wasm project
         * it not, `build`, `run` and `debug` will be disabled
         */
        if (currentPrjDir !== '') {
            const wamrFolder = fileSystem
                .readdirSync(currentPrjDir, {
                    withFileTypes: true,
                })
                .filter(
                    folder => folder.isDirectory() && folder.name === '.wamr'
                );

            if (wamrFolder.length !== 0) {
                isWasmProject = true;
                vscode.commands.executeCommand(
                    'setContext',
                    'ext.isWasmProject',
                    isWasmProject
                );
                if (
                    vscode.workspace
                        .getConfiguration()
                        .has('C_Cpp.default.systemIncludePath')
                ) {
                    let newIncludeInCppArr: string[] | undefined | null;

                    newIncludeInCppArr = vscode.workspace
                        .getConfiguration()
                        .get('C_Cpp.default.systemIncludePath');

                    const libcBuiltinHeaderPath = path.join(
                        extensionPath,
                        'resource/wamr-sdk/libc-builtin-sysroot/include'
                    );

                    if (newIncludeInCppArr !== undefined) {
                        /* in case the configuration has not been set up, push directly */
                        if (newIncludeInCppArr === null) {
                            newIncludeInCppArr = [];
                            newIncludeInCppArr.push(libcBuiltinHeaderPath);
                        } else {
                            /* if the configuration has been set up, check the condition */
                            if (
                                /* include libc-builtin-sysroot */
                                newIncludeInCppArr.indexOf(
                                    libcBuiltinHeaderPath
                                ) < 0
                            ) {
                                newIncludeInCppArr.push(libcBuiltinHeaderPath);
                            }
                        }

                        vscode.workspace
                            .getConfiguration()
                            .update(
                                'C_Cpp.default.systemIncludePath',
                                newIncludeInCppArr,
                                vscode.ConfigurationTarget.Workspace
                            );
                    }
                }
            }
        }
    }

    /* register debug configuration */
    wasmDebugConfigProvider = new WasmDebugConfigurationProvider(
        context.extensionPath
    );

    vscode.debug.registerDebugConfigurationProvider(
        'wamr-debug',
        wasmDebugConfigProvider
    );

    /* update ext.includePaths to show or hide 'Remove' button in menus */
    vscode.commands.executeCommand('setContext', 'ext.supportedFileType', [
        '.c',
        '.cpp',
        '.cxx',
    ]);

    if (readFromConfigFile() !== '') {
        const configData = JSON.parse(readFromConfigFile());
        includePathArr = configData['includePaths'];
        excludeFileArr = configData['excludeFiles'];

        if (Object.keys(configData['buildArgs']).length !== 0) {
            TargetConfigPanel.buildArgs = configData['buildArgs'];
        }
    }

    const disposableNewProj = vscode.commands.registerCommand(
        'wamride.newProject',
        () => {
            const okStr = 'Set up now';
            const cancelStr = 'Maybe later';
            const curWorkspace = vscode.workspace
                .getConfiguration()
                .get('WAMR-IDE.configWorkspace');

            /* if user has not set up workspace yet, prompt to set up */
            if (curWorkspace === '' || curWorkspace === undefined) {
                vscode.window
                    .showWarningMessage(
                        'Please setup your workspace firstly.',
                        okStr,
                        cancelStr
                    )
                    .then(item => {
                        if (item === okStr) {
                            vscode.commands.executeCommand(
                                'wamride.changeWorkspace'
                            );
                        } else {
                            return;
                        }
                    });
            } else if (!checkIfDirectoryExists(curWorkspace as string)) {
                vscode.window
                    .showWarningMessage(
                        'Invalid workspace:',
                        {
                            modal: true,
                            detail:
                                '' +
                                vscode.workspace
                                    .getConfiguration()
                                    .get('WAMR-IDE.configWorkspace') +
                                '',
                        },
                        okStr
                    )
                    .then(item => {
                        if (item === okStr) {
                            vscode.commands.executeCommand(
                                'wamride.changeWorkspace'
                            );
                        } else {
                            return;
                        }
                    });
            } else {
                NewProjectPanel.render(context);
            }
        }
    );

    const disposableTargetConfig = vscode.commands.registerCommand(
        'wamride.targetConfig',
        () => {
            if (currentPrjDir !== '') {
                TargetConfigPanel.render(context);
            } else {
                vscode.window.showWarningMessage(
                    'Please create and open project firstly.',
                    'OK'
                );
            }
        }
    );

    const disposableChangeWorkspace = vscode.commands.registerCommand(
        'wamride.changeWorkspace',
        async () => {
            const options: vscode.OpenDialogOptions = {
                canSelectFiles: false,
                canSelectFolders: true,
                openLabel: 'Select Workspace',
            };

            const workSpace = await vscode.window
                .showOpenDialog(options)
                .then(res => {
                    if (res) {
                        return res[0].fsPath as string;
                    } else {
                        return '';
                    }
                });

            /* update workspace value to vscode global settings */
            if (workSpace !== '' && workSpace !== undefined) {
                await vscode.workspace
                    .getConfiguration()
                    .update(
                        'WAMR-IDE.configWorkspace',
                        workSpace.trim(),
                        vscode.ConfigurationTarget.Global
                    )
                    .then(
                        () => {
                            vscode.window.showInformationMessage(
                                'Workspace has been set up successfully!'
                            );
                        },
                        () => {
                            vscode.window.showErrorMessage(
                                'Set up Workspace failed!'
                            );
                        }
                    );
            }
        }
    );

    const disposableBuild = vscode.commands.registerCommand(
        'wamride.build',
        async () => {
            if (!isWasmProject) {
                vscode.window.showErrorMessage('Build failed', {
                    modal: true,
                    detail: 'Current project is not wasm project, please open wasm project and try again.',
                });
                return;
            }

            try {
                /* check if docker images are ready before building */
                if (
                    (await checkIfDockerStarted()) &&
                    !(await checkIfDockerImagesExist(context))
                ) {
                    /**NOTE - if users select to skip install,
                     *        we should return rather than continue
                     *        the execution
                     */
                    if (
                        (await promptSetupDockerImages(context)) ===
                        SelectionOfPrompt.skip
                    ) {
                        return;
                    }
                }
            } catch (e) {
                vscode.window.showWarningMessage((e as Error).message);
                return;
            }

            generateCMakeFile(includePathArr, excludeFileArr);
            /* destroy the wasm-toolchain-ctr if it exists */
            vscode.commands
                .executeCommand(
                    'workbench.action.tasks.runTask',
                    'Destroy: Wasm-Container-Before-Build'
                )
                .then(() => {
                    const disposable = vscode.tasks.onDidEndTaskProcess(t => {
                        if (
                            t.execution.task.name ===
                            'Wasm-Container-Before-Build'
                        ) {
                            if (t.exitCode !== 0) {
                                disposable.dispose();
                                return;
                            }

                            /* execute the build task */
                            vscode.commands
                                .executeCommand(
                                    'workbench.action.tasks.runTask',
                                    'Build: Wasm'
                                )
                                .then(() => {
                                    /* destroy the wasm-toolchain-ctr after building */
                                    const disposableAft =
                                        vscode.tasks.onDidEndTask(a => {
                                            if (
                                                a.execution.task.name ===
                                                    'Wasm' &&
                                                a.execution.task.source ===
                                                    'Build'
                                            ) {
                                                vscode.commands
                                                    .executeCommand(
                                                        'workbench.action.tasks.runTask',
                                                        'Destroy: Wasm-Container-After-Build'
                                                    )
                                                    .then(() => {
                                                        /* dispose the event after this building process
                                                         */
                                                        disposableAft.dispose();
                                                    });
                                            }
                                        });
                                });
                            /* dispose the event after this building process */
                            disposable.dispose();
                        }
                    });
                });
        }
    );

    const disposableDebug = vscode.commands.registerCommand(
        'wamride.debug',
        async () => {
            if (!isWasmProject) {
                vscode.window.showErrorMessage('debug failed', {
                    modal: true,
                    detail: 'Current project is not wasm project, please open wasm project and try again.',
                });
                return;
            }

            /* we should check again whether the user installed lldb, as this can be skipped during activation */
            try {
                if (!isLLDBInstalled(context.extensionPath)) {
                    /**NOTE - if users select to skip install,
                     *        we should return rather than continue
                     *        the execution
                     */
                    if (
                        (await promptInstallLLDB(context.extensionPath)) ===
                        SelectionOfPrompt.skip
                    ) {
                        return;
                    }
                }

                if (
                    (await checkIfDockerStarted()) &&
                    !(await checkIfDockerImagesExist(context))
                ) {
                    /**NOTE - save as above lldb, should return if
                     *        users select to skip set up
                     */
                    if (
                        (await promptSetupDockerImages(context)) ===
                        SelectionOfPrompt.skip
                    ) {
                        return;
                    }
                }
            } catch (e) {
                vscode.window.showWarningMessage((e as Error).message);
                return;
            }

            /* refuse to debug if build process failed */
            if (!checkIfBuildSuccess()) {
                vscode.window.showErrorMessage('Debug failed', {
                    modal: true,
                    detail: 'Can not find WASM binary, please build WASM firstly.',
                });
                return;
            }

            /* show debug view */
            vscode.commands.executeCommand('workbench.view.debug');

            /* should destroy the wasm-debug-server-ctr before debugging */
            vscode.commands
                .executeCommand(
                    'workbench.action.tasks.runTask',
                    'Destroy: Wasm-Container-Before-Debug'
                )
                .then(() => {
                    /* execute the debug task when destroy task finish */
                    const disposableBfr = vscode.tasks.onDidEndTask(t => {
                        if (
                            t.execution.task.name ===
                            'Wasm-Container-Before-Debug'
                        ) {
                            vscode.commands
                                .executeCommand(
                                    'workbench.action.tasks.runTask',
                                    'Debug: Wasm'
                                )
                                .then(() => {
                                    vscode.debug
                                        .startDebugging(
                                            undefined,
                                            wasmDebugConfigProvider.getDebugConfig()
                                        )
                                        .then(() => {
                                            /* register to listen debug session finish event */
                                            const disposableAft =
                                                vscode.debug.onDidTerminateDebugSession(
                                                    s => {
                                                        if (
                                                            s.type !==
                                                            'wamr-debug'
                                                        ) {
                                                            return;
                                                        }

                                                        /* execute the task to destroy
                                                         * wasm-debug-server-ctr */
                                                        vscode.commands.executeCommand(
                                                            'workbench.action.tasks.runTask',
                                                            'Destroy: Wasm-Container-After-Debug'
                                                        );

                                                        /* execute the task to kill the terminal */
                                                        vscode.commands.executeCommand(
                                                            'workbench.action.terminal.kill',
                                                            'Debug: Wasm'
                                                        );

                                                        disposableAft.dispose();
                                                    }
                                                );
                                        });
                                });
                        }
                        disposableBfr.dispose();
                    });
                });
        }
    );

    const disposableRun = vscode.commands.registerCommand(
        'wamride.run',
        async () => {
            if (!isWasmProject) {
                vscode.window.showErrorMessage('run failed', {
                    modal: true,
                    detail: 'Current project is not wasm project, please open wasm project and try again.',
                });
                return;
            }

            try {
                /* check if docker images are set up before building */
                if (
                    (await checkIfDockerStarted()) &&
                    !(await checkIfDockerImagesExist(context))
                ) {
                    await promptSetupDockerImages(context);
                }
            } catch (e) {
                vscode.window.showWarningMessage((e as Error).message);
                return;
            }

            /* refuse to debug if build process failed */
            if (!checkIfBuildSuccess()) {
                vscode.window.showErrorMessage('Debug failed', {
                    modal: true,
                    detail: 'Can not find WASM binary, please build WASM firstly.',
                });
                return;
            }

            vscode.commands
                .executeCommand(
                    'workbench.action.tasks.runTask',
                    'Destroy: Wasm-Container-Before-Run'
                )
                .then(() => {
                    const disposableAft = vscode.tasks.onDidEndTaskProcess(
                        e => {
                            if (
                                e.execution.task.name ===
                                'Wasm-Container-Before-Run'
                            ) {
                                /* make sure that run wasm task will be executed when destroy task finish */
                                vscode.commands
                                    .executeCommand(
                                        'workbench.action.tasks.runTask',
                                        'Run: Wasm'
                                    )
                                    .then(() => {
                                        if (e.exitCode !== 0) {
                                            disposableAft.dispose();
                                            return;
                                        }
                                    });
                                disposableAft.dispose();
                            }
                        }
                    );
                });
        }
    );

    const disposableToggleIncludePath = vscode.commands.registerCommand(
        'wamride.build.toggleStateIncludePath',
        fileUri => {
            const path =
                fileUri._fsPath !== null && fileUri._fsPath !== undefined
                    ? fileUri._fsPath
                    : vscode.Uri.parse(fileUri.path as string).fsPath;
            const pathRelative = path.replace(currentPrjDir, '..');

            if (includePathArr.indexOf(pathRelative) > -1) {
                /* this folder has been added to include path, remove it */
                includePathArr = includePathArr.filter(value => {
                    return value !== pathRelative;
                });
            } else {
                includePathArr.push(pathRelative);
            }

            writeIntoConfigFile(
                includePathArr,
                excludeFileArr,
                TargetConfigPanel.buildArgs
            );

            decorationProvider.updateDecorationsForSource(fileUri);
        }
    );

    const disposableToggleExcludeFile = vscode.commands.registerCommand(
        'wamride.build.toggleStateExclude',
        fileUri => {
            const path =
                fileUri._fsPath !== null && fileUri._fsPath !== undefined
                    ? fileUri._fsPath
                    : vscode.Uri.parse(fileUri.path as string).fsPath;

            /* replace the current project absolute path with .. to change to relative path */
            const pathRelative = path.replace(currentPrjDir, '..');

            if (excludeFileArr.indexOf(pathRelative) > -1) {
                excludeFileArr = excludeFileArr.filter(val => {
                    return val !== pathRelative;
                });
            } else {
                excludeFileArr.push(pathRelative);
            }

            writeIntoConfigFile(
                includePathArr,
                excludeFileArr,
                TargetConfigPanel.buildArgs
            );

            /* update decoration for this source file */
            decorationProvider.updateDecorationsForSource(fileUri);
        }
    );

    const disposableOpenFolder = vscode.commands.registerCommand(
        'wamride.openFolder',
        () => {
            /* get projects list under current workspace */
            const okStr = 'Set up now';
            const cancelStr = 'Maybe later';
            const createStr = 'Create now';
            const curWorkspace = vscode.workspace
                .getConfiguration()
                .get('WAMR-IDE.configWorkspace') as string;

            /* if user has not set up workspace yet, prompt to set up */
            if (curWorkspace === '' || curWorkspace === undefined) {
                vscode.window
                    .showWarningMessage(
                        'Please setup your workspace firstly.',
                        okStr,
                        cancelStr
                    )
                    .then(item => {
                        if (item === okStr) {
                            vscode.commands.executeCommand(
                                'wamride.changeWorkspace'
                            );
                        } else {
                            return;
                        }
                    });
            } else if (!checkIfDirectoryExists(curWorkspace as string)) {
                vscode.window
                    .showWarningMessage(
                        'Invalid workspace:',
                        {
                            modal: true,
                            detail:
                                '' +
                                vscode.workspace
                                    .getConfiguration()
                                    .get('WAMR-IDE.configWorkspace') +
                                '',
                        },
                        okStr
                    )
                    .then(item => {
                        if (item === okStr) {
                            vscode.commands.executeCommand(
                                'wamride.changeWorkspace'
                            );
                        } else {
                            return;
                        }
                    });
            } else {
                /* get all directories within directory, ignore files */
                let directoryArrDirent, directoryArr;
                try {
                    directoryArrDirent = fileSystem.readdirSync(curWorkspace, {
                        withFileTypes: true,
                    });
                } catch (err) {
                    vscode.window.showErrorMessage(
                        'Read projects from current workspace failed.'
                    );
                }

                if (directoryArrDirent !== undefined) {
                    directoryArr = directoryArrDirent
                        .filter(dirent => dirent.isDirectory())
                        .map(dirent => dirent.name);

                    const projFilesArr = directoryArr.filter(obj => {
                        if (checkIfWasmProj(path.join(curWorkspace, obj))) {
                            return true;
                        }
                    });

                    if (projFilesArr.length === 0) {
                        vscode.window
                            .showWarningMessage(
                                'Current workspace is empty, please create your project firstly.',
                                createStr,
                                cancelStr
                            )
                            .then(item => {
                                if (item === createStr) {
                                    vscode.commands.executeCommand(
                                        'wamride.newProject'
                                    );
                                } else {
                                    return;
                                }
                            });
                    } else {
                        vscode.window
                            .showQuickPick(projFilesArr, {
                                title: 'Select project',
                                placeHolder: 'Please select project',
                            })
                            .then(option => {
                                if (!option) {
                                    return;
                                }

                                const path = curWorkspace.concat(
                                    osPlatform === 'win32'
                                        ? '\\'
                                        : osPlatform === 'linux' ||
                                          osPlatform === 'darwin'
                                        ? '/'
                                        : '',
                                    option
                                );

                                /* open the selected wasm project */
                                openWindowWithSituation(vscode.Uri.file(path));
                            });
                    }
                }
            }
        }
    );

    context.subscriptions.push(
        disposableNewProj,
        disposableTargetConfig,
        disposableChangeWorkspace,
        disposableBuild,
        disposableRun,
        disposableToggleIncludePath,
        disposableOpenFolder,
        disposableToggleExcludeFile,
        disposableDebug
    );

    try {
        if (!isLLDBInstalled(context.extensionPath)) {
            await promptInstallLLDB(context.extensionPath);
        }

        if (
            (await checkIfDockerStarted()) &&
            !(await checkIfDockerImagesExist(context))
        ) {
            await promptSetupDockerImages(context);
        }
    } catch (e) {
        vscode.window.showWarningMessage((e as Error).message);
    }
}

function openWindowWithSituation(uri: vscode.Uri) {
    /**
     * check if the workspace folder is empty,
     * if yes, open new window, else open in current window
     */
    const isWorkspaceEmpty = !vscode.workspace.workspaceFolders?.[0]
        ? true
        : false;

    isWorkspaceEmpty === false
        ? vscode.commands.executeCommand('vscode.openFolder', uri, {
              forceNewWindow: true,
          })
        : vscode.commands.executeCommand('vscode.openFolder', uri);

    return;
}

interface BuildArgs {
    outputFileName: string;
    initMemorySize: string;
    maxMemorySize: string;
    stackSize: string;
    exportedSymbols: string;
    hostManagedHeapSize: string;
}

/**
 * @param: includePathArr
 * @param: excludeFileArr
 *   Get current includePathArr and excludeFileArr from the json string that
 *   will be written into compilation_config.json
 */
export function writeIntoConfigFile(
    includePathArr: string[],
    excludeFileArr: string[],
    buildArgs?: BuildArgs
): void {
    const jsonStr = JSON.stringify(
        {
            includePaths: includePathArr,
            excludeFiles: excludeFileArr,
            buildArgs: buildArgs ? buildArgs : '{}',
        },
        null,
        '\t'
    );

    const prjConfigDir = path.join(currentPrjDir, '.wamr');
    const configFilePath = path.join(prjConfigDir, 'compilation_config.json');
    writeIntoFile(configFilePath, jsonStr);
}

export function readFromConfigFile(): string {
    const prjConfigDir = path.join(currentPrjDir, '.wamr');
    const configFilePath = path.join(prjConfigDir, 'compilation_config.json');
    return readFromFile(configFilePath);
}

/**
 * will be triggered when the user clicking `build` button
 */
function generateCMakeFile(
    includePathArr: string[],
    excludeFileArr: string[]
): void {
    // -Wl,--export=${EXPORT_SYMBOLS}
    const srcFilePath = path.join(currentPrjDir, 'src');
    const prjConfigDir = path.join(currentPrjDir, '.wamr');
    const cmakeFilePath = path.join(prjConfigDir, 'project.cmake');

    let strIncludeList = 'set (PROJECT_INCLUDES';
    let strSrcList = 'set (PROJECT_SRC_LIST';

    let strOutputFileName = 'set (OUTPUT_FILE_NAME';
    let strInitMemSize = 'set (INIT_MEM_SIZE';
    let strMaxMemSize = 'set (MAX_MEM_SIZE';
    let strStackSize = 'set (STACK_SIZE';
    let strExportedSymbols = 'set (EXPORTED_SYMBOLS';

    let fullStr = '';
    let i, s, e: number;

    /* change the absolute path into relative path */
    const _re = currentPrjDir;
    const _substr = '${CMAKE_CURRENT_SOURCE_DIR}/..';

    /**
     * set PROJECT_SRC_LIST
     *     default ADD every c OR c++ OR cpp under the src/ path
     *     except the files saved in the excludeFiles array
     */

    const srcPathArr = getAllSrcFiles(srcFilePath);

    if (srcPathArr === undefined) {
        return;
    }

    for (s = 0; s < srcPathArr.length; s++) {
        if (
            excludeFileArr.indexOf(
                srcPathArr[s].path.replace(currentPrjDir, '..')
            ) === -1
        ) {
            /* replace currentPrjDir with ${CMAKE_CURRENT_SOURCE_DIR} */
            const newStr = srcPathArr[s].path
                .replace(_re, _substr)
                .replace(/\\/g, '/');

            strSrcList = strSrcList.concat(' ', newStr);
        }
    }
    strSrcList = strSrcList.concat(' )');

    for (i = 0; i < includePathArr.length; i++) {
        const newStr = includePathArr[i]
            .replace(/../, _substr)
            .replace(/\\/g, '/');
        strIncludeList = strIncludeList.concat(' ', newStr);
    }
    strIncludeList = strIncludeList.concat(' )');

    /* set up user customized input in configBuildArgs webview */
    strOutputFileName = strOutputFileName.concat(
        ' ',
        TargetConfigPanel.buildArgs.outputFileName + ')'
    );

    strInitMemSize = strInitMemSize.concat(
        ' ',
        TargetConfigPanel.buildArgs.initMemorySize + ')'
    );

    strMaxMemSize = strMaxMemSize.concat(
        ' ',
        TargetConfigPanel.buildArgs.maxMemorySize + ')'
    );

    strStackSize = strStackSize.concat(
        ' ',
        TargetConfigPanel.buildArgs.stackSize + ')'
    );

    const exportedSymbolArr =
        TargetConfigPanel.buildArgs.exportedSymbols.split(',');

    strExportedSymbols = strExportedSymbols.concat(' "');

    for (e = 0; e < exportedSymbolArr.length; e++) {
        strExportedSymbols = strExportedSymbols.concat(
            ' -Wl,',
            '--export=',
            exportedSymbolArr[e]
        );
    }

    strExportedSymbols = strExportedSymbols.concat('")');

    fullStr = strOutputFileName
        .concat('\n', strInitMemSize)
        .concat('\n', strMaxMemSize)
        .concat('\n', strStackSize)
        .concat('\n', strExportedSymbols)
        .concat('\n', strSrcList)
        .concat('\n', strIncludeList);

    writeIntoFile(cmakeFilePath, fullStr);
}

function getAllSrcFiles(_path: string) {
    try {
        const entries = fileSystem.readdirSync(_path, {
            withFileTypes: true,
        });

        const files = entries
            .filter(
                /* filter files mismatch .c |.cpp |.cxx */
                file =>
                    !file.isDirectory() && file.name.match('(.c|.cpp|.cxx)$')
            )
            .map(file => ({
                path: path.join(_path, file.name),
            }));

        const folders = entries.filter(folder => folder.isDirectory());

        for (const folder of folders) {
            const fileArr = getAllSrcFiles(path.join(_path, folder.name));
            fileArr ? files.push(...fileArr) : '';
        }

        return files;
    } catch (error) {
        vscode.window.showErrorMessage(error as string);
    }
}

function checkIfBuildSuccess(): boolean {
    try {
        let wasmExist = false;
        const entries = fileSystem.readdirSync(
            path.join(currentPrjDir, 'build'),
            {
                withFileTypes: true,
            }
        );

        entries.map(e => {
            if (e.name.match('(.wasm)$')) {
                wasmExist = true;
            }
        });

        return wasmExist;
    } catch {
        return false;
    }
}

function checkIfWasmProj(path: string): boolean {
    try {
        let isWasmProj = false;
        const entries = fileSystem.readdirSync(path, {
            withFileTypes: true,
        });

        entries.map(e => {
            if (e.isDirectory() && e.name === '.wamr') {
                isWasmProj = true;
            }
        });

        return isWasmProj;
    } catch {
        return false;
    }
}
