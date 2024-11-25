/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { getWAMRExtensionVersion } from './lldbUtilities';
import { downloadFile, unzipFile } from './directoryUtilities';
import { SelectionOfPrompt, Status } from '../constants';

const DOCKER_IMAGES_TEM_FOLDER_NAME = 'docker-resource';

type SelectionStatus = SelectionOfPrompt | Status;

const execShell = (cmd: string) =>
    new Promise<string>((resolve, reject) => {
        cp.exec(cmd, (error, result) => {
            if (error) {
                return reject(error);
            }
            return resolve(result);
        });
    });

export async function promptSetupDockerImages(
    context: vscode.ExtensionContext
): Promise<SelectionStatus> {
    const extensionPath = context.extensionPath;
    const response = await vscode.window.showWarningMessage(
        'Necessary docker images are not found. Setup now?',
        SelectionOfPrompt.setUp,
        SelectionOfPrompt.skip
    );

    if (response === SelectionOfPrompt.skip) {
        return response;
    }

    const downloadUrlArray = getDockerImagesDownloadUrl(context);

    const destinationFolder = path.resolve(
        extensionPath,
        'resource',
        DOCKER_IMAGES_TEM_FOLDER_NAME
    );

    if (!fs.existsSync(destinationFolder)) {
        fs.mkdirSync(destinationFolder);
    }

    vscode.window.showInformationMessage(`Downloading Docker Images...`);

    for (const url of downloadUrlArray) {
        const imageZipName = path.basename(url);
        const imageStorePath = path.join(destinationFolder, imageZipName);
        await downloadFile(url, imageStorePath);

        /**
         * extract docker image tar package to
         * '${destinationFolder}'
         */
        const dockerImageFile = await unzipFile(imageStorePath, filename =>
            path.join(destinationFolder, filename)
        );
        /* give access before loading */
        dockerImageFile.forEach(file => fs.chmodSync(file, '0775'));

        /**NOTE - load docker image tar package to host
         *        right now there are just one file
         *        `docker-image-name.tar` inside so we can
         *        directly use files[0] here, should be modified
         *        if the package's files change
         */
        await execShell(`docker load -i ${dockerImageFile[0]}`);
    }

    /* remove the DOCKER_IMAGES_TEM_FOLDER */
    fs.rmSync(destinationFolder, { recursive: true, force: true });

    vscode.window.showInformationMessage(
        `Docker images are ready, please run '$docker images' to check.`
    );

    return Status.done;
}

export async function checkIfDockerStarted(): Promise<boolean> {
    try {
        await execShell('docker images');
        return true;
    } catch (e) {
        vscode.window.showWarningMessage((e as Error).message);
        return false;
    }
}

export async function checkIfDockerImagesExist(
    context: vscode.ExtensionContext
): Promise<boolean> {
    try {
        /* the tag of images is equal to extension's version */
        const imageTag = getWAMRExtensionVersion(context.extensionPath);
        await execShell(
            `docker image inspect wasm-debug-server:${imageTag} wasm-toolchain:${imageTag}`
        );
        return true;
    } catch (e) {
        return false;
    }
}

function getDockerImagesDownloadUrl(
    context: vscode.ExtensionContext
): string[] {
    const wamrVersion = getWAMRExtensionVersion(context.extensionPath);
    const wamrReleaseUrl = `https://github.com/bytecodealliance/wasm-micro-runtime/releases/download/WAMR`;

    return [
        `${wamrReleaseUrl}-${wamrVersion}/wasm-debug-server-${wamrVersion}.zip`,
        `${wamrReleaseUrl}-${wamrVersion}/wasm-toolchain-${wamrVersion}.zip`,
    ];
}
