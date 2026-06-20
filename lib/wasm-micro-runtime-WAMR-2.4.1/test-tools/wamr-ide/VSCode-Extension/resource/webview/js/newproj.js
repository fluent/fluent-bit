/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

const vscode = acquireVsCodeApi();

document.getElementById('btn_submit').onclick = () => {
    submitFunc();
};

function submitFunc() {
    let projectName = document.getElementById('ipt_projName').value;
    let template = document.getElementById('select_dropdown').value;

    vscode.postMessage({
        command: 'create_new_project',
        projectName: projectName,
        template: template,
    });

    /* get msg from ext */
    window.addEventListener('message', event => {
        const message = event.data;
        switch (message.command) {
            /* send command to open the project */
            case 'proj_creation_finish':
                vscode.postMessage({
                    command: 'open_project',
                    projectName: message.prjName,
                });
                break;
            default:
                break;
        }
    });
}
