/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

import { Uri, Webview } from 'vscode';

export function getUri(
    webview: Webview,
    extensionUri: Uri,
    pathList: string[]
): Uri {
    return webview.asWebviewUri(Uri.joinPath(extensionUri, ...pathList));
}
