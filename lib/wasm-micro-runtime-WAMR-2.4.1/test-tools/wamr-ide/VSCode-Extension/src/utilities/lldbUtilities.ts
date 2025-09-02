/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import {
    checkIfFileExists,
    downloadFile,
    unzipFile,
} from './directoryUtilities';
import { SelectionOfPrompt } from '../constants';

const LLDB_RESOURCE_DIR = 'resource/debug';
const LLDB_OS_DOWNLOAD_URL_SUFFIX_MAP: Partial<
    Record<NodeJS.Platform, string>
> = {
    linux: 'x86_64-ubuntu-20.04',
    darwin: 'universal-macos-latest',
};

const WAMR_LLDB_NOT_SUPPORTED_ERROR = new Error(
    'WAMR LLDB is not supported on this platform'
);

function getLLDBUnzipFilePath(destinationFolder: string, filename: string) {
    const dirs = filename.split('/');
    if (dirs[0] === 'wamr-lldb') {
        dirs.shift();
    }

    return path.join(destinationFolder, ...dirs);
}

export function getWAMRExtensionVersion(extensionPath: string): string {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require(path.join(extensionPath, 'package.json')).version;
}

function getLLDBDownloadUrl(extensionPath: string): string {
    const wamrVersion = getWAMRExtensionVersion(extensionPath);
    const lldbOsUrlSuffix = LLDB_OS_DOWNLOAD_URL_SUFFIX_MAP[os.platform()];

    if (!lldbOsUrlSuffix) {
        throw WAMR_LLDB_NOT_SUPPORTED_ERROR;
    }

    return `https://github.com/bytecodealliance/wasm-micro-runtime/releases/download/WAMR-${wamrVersion}/wamr-lldb-${wamrVersion}-${lldbOsUrlSuffix}.zip`;
}

export function isLLDBInstalled(extensionPath: string): boolean {
    const lldbOSDir = os.platform();
    const lldbBinaryPath = path.join(
        extensionPath,
        LLDB_RESOURCE_DIR,
        lldbOSDir,
        'bin',
        'lldb'
    );
    return checkIfFileExists(lldbBinaryPath);
}

export async function promptInstallLLDB(
    extensionPath: string
): Promise<SelectionOfPrompt> {
    const response = await vscode.window.showWarningMessage(
        'No LLDB instance found. Setup now?',
        SelectionOfPrompt.setUp,
        SelectionOfPrompt.skip
    );

    if (response === SelectionOfPrompt.skip) {
        return response;
    }

    await downloadLldb(extensionPath);

    return SelectionOfPrompt.setUp;
}

export async function downloadLldb(extensionPath: string): Promise<void> {
    const downloadUrl = getLLDBDownloadUrl(extensionPath);
    const destinationDir = os.platform();

    if (!downloadUrl) {
        throw WAMR_LLDB_NOT_SUPPORTED_ERROR;
    }

    const lldbDestinationFolder = path.join(
        extensionPath,
        LLDB_RESOURCE_DIR,
        destinationDir
    );
    const lldbZipPath = path.join(lldbDestinationFolder, 'bundle.zip');

    vscode.window.showInformationMessage(`Downloading LLDB...`);

    await downloadFile(downloadUrl, lldbZipPath);

    vscode.window.showInformationMessage(
        `LLDB downloaded to ${lldbZipPath}. Installing...`
    );

    const lldbFiles = await unzipFile(lldbZipPath, filename =>
        getLLDBUnzipFilePath(lldbDestinationFolder, filename)
    );
    // Allow execution of lldb
    lldbFiles.forEach(file => fs.chmodSync(file, '0775'));

    vscode.window.showInformationMessage(
        `LLDB installed at ${lldbDestinationFolder}`
    );

    // Remove the bundle.zip
    fs.unlinkSync(lldbZipPath);
}
