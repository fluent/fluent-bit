/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import fileSystem = require('fs');
import vscode = require('vscode');
import path = require('path');
import os = require('os');
import request = require('request');
import yauzl = require('yauzl');

/**
 *
 * @param path destination path
 */
export function createDirectory(
    dest: string,
    mode: string | number | null | undefined = undefined
): boolean {
    try {
        if (fileSystem.existsSync(dest)) {
            if (fileSystem.lstatSync(dest).isDirectory()) {
                return true;
            } else {
                return false;
            }
        }

        if (!path) {
            return false;
        }

        const parent = path.dirname(dest);
        if (!createDirectory(parent, mode)) {
            return false;
        }

        fileSystem.mkdirSync(dest, mode);
        return true;
    } catch (error) {
        vscode.window.showErrorMessage(error as string);
        return false;
    }
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function copyFiles(src: string, dest: string, flags?: number): boolean {
    try {
        fileSystem.copyFileSync(src, dest);
        return true;
    } catch (error) {
        vscode.window.showErrorMessage(error as string);
        return false;
    }
}

export function writeIntoFile(path: string, data: string): void {
    try {
        fileSystem.writeFileSync(path, data, null);
    } catch (err) {
        vscode.window.showErrorMessage(err as string);
    }
}

export function readFromFile(path: string): string {
    try {
        const data = fileSystem.readFileSync(path, { encoding: 'utf-8' });
        return data as string;
    } catch (err) {
        vscode.window.showErrorMessage(err as string);
        return '';
    }
}

export function writeIntoFileAsync(
    path: string,
    data: string,
    callback: fileSystem.NoParamCallback
): void {
    try {
        fileSystem.writeFile(path, data, callback);
    } catch (err) {
        vscode.window.showErrorMessage(err as string);
        return;
    }
}

export function checkIfPathExists(path: string): boolean {
    try {
        if (fileSystem.existsSync(path)) {
            return true;
        } else {
            return false;
        }
    } catch (err) {
        vscode.window.showErrorMessage(err as string);
        return false;
    }
}

export function checkIfDirectoryExists(path: string): boolean {
    const doesPathExist = checkIfPathExists(path);
    if (doesPathExist) {
        return fileSystem.lstatSync(path).isDirectory();
    }
    return false;
}

export function checkIfFileExists(path: string): boolean {
    const doesPathExist = checkIfPathExists(path);
    if (doesPathExist) {
        return fileSystem.lstatSync(path).isFile();
    }
    return false;
}

export function checkFolderName(folderName: string): boolean {
    let invalidCharacterArr: string[] = [];
    let valid = true;

    if (folderName.length > 255) {
        valid = false;
    }

    if (os.platform() === 'win32') {
        invalidCharacterArr = ['\\', '/', ':', '?', '*', '"', '|', '<', '>'];
    } else if (os.platform() === 'linux' || os.platform() === 'darwin') {
        invalidCharacterArr = ['/'];
    }

    invalidCharacterArr.forEach(function (c) {
        if (folderName.indexOf(c) !== -1) {
            valid = false;
        }
    });

    return valid;
}

export function downloadFile(
    url: string,
    destinationPath: string
): Promise<void> {
    return new Promise((resolve, reject) => {
        const file = fileSystem.createWriteStream(destinationPath);
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const stream = request(url, undefined, (error, response, body) => {
            if (response.statusCode !== 200) {
                reject(
                    new Error(
                        `Download from ${url} failed with ${response.statusMessage}`
                    )
                );
            }
        }).pipe(file);
        stream.on('close', resolve);
        stream.on('error', reject);
    });
}

export function unzipFile(
    sourcePath: string,
    getDestinationFileName: (entryName: string) => string
): Promise<string[]> {
    return new Promise((resolve, reject) => {
        const unzippedFilePaths: string[] = [];
        yauzl.open(
            sourcePath,
            { lazyEntries: true },
            function (error, zipfile) {
                if (error) {
                    reject(error);
                    return;
                }
                zipfile.readEntry();
                zipfile.on('entry', function (entry) {
                    // This entry is a directory so skip it
                    if (/\/$/.test(entry.fileName)) {
                        zipfile.readEntry();
                        return;
                    }

                    zipfile.openReadStream(entry, function (error, readStream) {
                        if (error) {
                            reject(error);
                            return;
                        }
                        readStream.on('end', () => zipfile.readEntry());
                        const destinationFileName = getDestinationFileName(
                            entry.fileName
                        );
                        fileSystem.mkdirSync(
                            path.dirname(destinationFileName),
                            { recursive: true }
                        );

                        const file =
                            fileSystem.createWriteStream(destinationFileName);
                        readStream.pipe(file).on('error', reject);
                        unzippedFilePaths.push(destinationFileName);
                    });
                });
                zipfile.on('end', function () {
                    zipfile.close();
                    resolve(unzippedFilePaths);
                });
            }
        );
    });
}
