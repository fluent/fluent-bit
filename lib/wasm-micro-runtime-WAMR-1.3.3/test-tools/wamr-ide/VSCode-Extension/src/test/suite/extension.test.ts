/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import { DebugProtocol } from '@vscode/debugprotocol';
import { after, before, test, suite } from 'mocha';
import { assert } from 'chai';
import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as os from 'os';
import {
    WasmDebugConfig,
    WasmDebugConfigurationProvider,
} from '../../debugConfigurationProvider';
import {
    EXTENSION_PATH,
    clearAllBp,
    setBpAtMarker,
    compileRustToWasm,
} from './utils';
import { downloadLldb, isLLDBInstalled } from '../../utilities/lldbUtilities';

suite('Unit Tests', function () {
    test('DebugConfigurationProvider init commands', function () {
        const testExtensionPath = '/test/path/';
        const provider = new WasmDebugConfigurationProvider(testExtensionPath);

        assert.includeMembers(
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            provider.getDebugConfig().initCommands!,
            [`command script import ${testExtensionPath}/formatters/rust.py`],
            'Debugger init commands did not contain '
        );
    });

    test('DebugConfigurationProvider resolve configuration', function () {
        const testExtensionPath = '/test/path/';
        const provider = new WasmDebugConfigurationProvider(testExtensionPath);

        const actual = provider.resolveDebugConfiguration(undefined, {
            type: 'wamr-debug',
            name: 'Attach',
            request: 'attach',
            initCommands: [],
            attachCommands: [
                'process connect -p wasm connect://123.456.789.1:1237',
            ],
        });

        assert.deepEqual(
            actual,
            {
                type: 'wamr-debug',
                name: 'Attach',
                request: 'attach',
                stopOnEntry: true,
                initCommands: [],
                attachCommands: [
                    'process connect -p wasm connect://123.456.789.1:1237',
                ],
            },
            'Configuration did not match the expected configuration after calling resolveDebugConfiguration()'
        );
    });
});

suite('Inegration Tests', function () {
    let debuggerProcess: cp.ChildProcessWithoutNullStreams;
    const port = 1239;
    const downloadTimeout = 60 * 1000;

    before(async function () {
        // timeout of 20 seconds
        this.timeout(20 * 1000);
        // Download LLDB if necessary. Should be available in the CI. Only for local execution.
        if (!isLLDBInstalled(EXTENSION_PATH)) {
            this.timeout(downloadTimeout);
            console.log('Downloading LLDB. This might take a moment...');
            await downloadLldb(EXTENSION_PATH);
            assert.isTrue(
                isLLDBInstalled(EXTENSION_PATH),
                'LLDB was not installed correctly'
            );
        }

        compileRustToWasm();

        const platform = os.platform();
        assert.isTrue(
            platform === 'darwin' || platform === 'linux',
            `Tests do not support your platform: ${platform}`
        );
        const iWasmPath = path.resolve(
            `${EXTENSION_PATH}/../../../product-mini/platforms/${platform}/build/iwasm`
        );
        const testWasmFilePath = `${EXTENSION_PATH}/resource/test/test.wasm`;

        debuggerProcess = cp.spawn(
            iWasmPath,
            [`-g=127.0.0.1:${port}`, testWasmFilePath],
            {}
        );

        debuggerProcess.stderr.on('data', data => {
            console.log(`Error from debugger process: ${data}`);
        });
    });

    after(async function () {
        await vscode.debug.stopDebugging();
        debuggerProcess.kill();
    });

    test('Rust formatters', async function () {
        // timeout of 1 minutes
        this.timeout(60 * 1000);
        clearAllBp();
        setBpAtMarker(`${EXTENSION_PATH}/resource/test/test.rs`, 'BP_MARKER_1');

        const getVariables = new Promise<DebugProtocol.Variable[]>(
            (resolve, reject) => {
                vscode.debug.registerDebugAdapterTrackerFactory('wamr-debug', {
                    createDebugAdapterTracker: function () {
                        return {
                            // The debug adapter has sent a Debug Adapter Protocol message to the editor.
                            onDidSendMessage: (
                                message: DebugProtocol.ProtocolMessage
                            ) => {
                                if (message.type === 'response') {
                                    const m = message as DebugProtocol.Response;
                                    if (m.command === 'variables') {
                                        const res =
                                            m as DebugProtocol.VariablesResponse;
                                        resolve(res.body.variables);
                                    }
                                }
                            },
                            onError: (error: Error) => {
                                reject(
                                    'An error occurred before vscode reached the breakpoint: ' +
                                        error
                                );
                            },
                            onExit: (code: number | undefined) => {
                                reject(
                                    `Debugger exited before vscode reached the breakpoint with code: ${code}`
                                );
                            },
                        };
                    },
                });
            }
        );

        const config: WasmDebugConfig = {
            type: 'wamr-debug',
            request: 'attach',
            name: 'Attach Debugger',
            stopOnEntry: false,
            initCommands: [
                `command script import ${EXTENSION_PATH}/formatters/rust.py`,
            ],
            attachCommands: [
                `process connect -p wasm connect://127.0.0.1:${port}`,
            ],
        };

        if (os.platform() === 'win32' || os.platform() === 'darwin') {
            config.initCommands?.push('platform select remote-linux');
        }

        try {
            await vscode.debug.startDebugging(undefined, config);
        } catch (e) {
            assert.fail('Could not connect to debug adapter');
        }

        // wait until vs code has reached breakpoint and has requested the variables.
        const variables = await getVariables;
        const namesToVariables = variables.reduce(
            (acc: { [name: string]: DebugProtocol.Variable }, c) => {
                if (c.evaluateName) {
                    acc[c.evaluateName] = c;
                }
                return acc;
            },
            {}
        );

        assert.includeMembers(
            Object.keys(namesToVariables),
            ['vector', 'map', 'string', 'slice', 'deque', 'ref_cell'],
            'The Debugger did not return all expected debugger variables.'
        );

        // Vector
        assert.equal(
            namesToVariables['vector'].value,
            ' (5) vec![1, 2, 3, 4, 12]',
            'The Vector summary string looks different than expected'
        );

        // Map
        assert.equal(
            namesToVariables['map'].value,
            ' size=5, capacity=8',
            'The Map summary string looks different than expected'
        );

        // String
        assert.equal(
            namesToVariables['string'].value,
            ' "this is a string"',
            'The String summary string looks different than expected'
        );

        // Slice
        assert.equal(
            namesToVariables['slice'].value,
            ' "ello"',
            'The Slice summary string looks different than expected'
        );

        // Deque
        // TODO: The deque format conversion have some problem now
        // -alloc::collections::vec_deque::VecDeque<int, alloc::alloc::Global> @ 0xfff1c
        // + (5) VecDeque[1, 2, 3, 4, 5]
        // assert.equal(
        //     namesToVariables['deque'].value,
        //     ' (5) VecDeque[1, 2, 3, 4, 5]',
        //     'The Deque summary string looks different than expected'
        // );

        // RefCell
        assert.equal(
            namesToVariables['ref_cell'].value,
            ' 5',
            'The RefCell summary string looks different than expected'
        );
    });
});
