/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import fileSystem = require('fs');
import vscode = require('vscode');
import path = require('path');
import os = require('os');

/**
 *
 * @param path destination path
 */
export function CreateDirectory(
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

        let parent = path.dirname(dest);
        if (!CreateDirectory(parent, mode)) {
            return false;
        }

        fileSystem.mkdirSync(dest, mode);
        return true;
    } catch (error) {
        vscode.window.showErrorMessage(error as string);
        return false;
    }
}

export function CopyFiles(src: string, dest: string, flags?: number): boolean {
    try {
        fileSystem.copyFileSync(src, dest);
        return true;
    } catch (error) {
        vscode.window.showErrorMessage(error as string);
        return false;
    }
}

export function WriteIntoFile(path: string, data: string): void {
    try {
        fileSystem.writeFileSync(path, data, null);
    } catch (err) {
        vscode.window.showErrorMessage(err as string);
    }
}

export function ReadFromFile(path: string): string {
    try {
        let data = fileSystem.readFileSync(path, { encoding: 'utf-8' });
        return data as string;
    } catch (err) {
        vscode.window.showErrorMessage(err as string);
        return '';
    }
}

export function WriteIntoFileAsync(
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

export function CheckIfDirectoryExist(path: string): boolean {
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

export function checkFolderName(folderName: string) {
    let invalidCharacterArr: string[] = [];
    var valid = true;

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
