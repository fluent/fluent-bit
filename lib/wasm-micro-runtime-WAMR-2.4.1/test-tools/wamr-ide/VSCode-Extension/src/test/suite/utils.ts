/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import { assert } from 'chai';
import * as vscode from 'vscode';
import { Range, SourceBreakpoint } from 'vscode';
import * as fs from 'fs';
import path = require('path');
import * as cp from 'child_process';

export const EXTENSION_PATH = path.resolve(`${__dirname}/../../..`);

// clears all set breakpoints
export function clearAllBp(): void {
    vscode.debug.removeBreakpoints(vscode.debug.breakpoints);
}

// Inserts a breakpoint in a file at the first occurrence of bpMarker
export function setBpAtMarker(file: string, bpMarker: string): void {
    const uri = vscode.Uri.file(file);
    const data = fs.readFileSync(uri.path, 'utf8');
    const line = data.split('\n').findIndex(line => line.includes(bpMarker));
    assert.notStrictEqual(
        line,
        -1,
        'Could not find breakpoint marker in source file'
    );
    const position = new vscode.Position(line, 0);
    const bp = new SourceBreakpoint(
        new vscode.Location(uri, new Range(position, position)),
        true
    );
    vscode.debug.addBreakpoints([bp]);
}

// compiles resources/test/test.rs to test.wasm
export function compileRustToWasm(): void {
    const testResourceFolder = `${EXTENSION_PATH}/resource/test`;
    // compile with debug symbols and no optimization
    const cmd = `rustc --target wasm32-wasip1 ${testResourceFolder}/test.rs -g -C opt-level=0 -o ${testResourceFolder}/test.wasm`;

    try {
        cp.execSync(cmd, { stdio: [null, null, process.stderr] });
    } catch (e) {
        assert.fail(`Compilation of example rust file failed with error: ${e}`);
    }
    assert.isTrue(
        fs.existsSync(`${testResourceFolder}/test.wasm`),
        'Could not find wasm file WASM file to run debugger on.'
    );
}
