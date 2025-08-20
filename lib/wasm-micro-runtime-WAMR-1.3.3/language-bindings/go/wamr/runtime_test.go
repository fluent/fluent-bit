/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

package wamr

import (
    "github.com/stretchr/testify/assert"
    "testing"
)

func TestRuntime(t *testing.T) {
    res := false
    if (Runtime() != nil) {
        res = true;
    }
    assert.Equal(t, res, true)

    err := Runtime().Init()
    assert.NoError(t, err)
    Runtime().Destroy()

    err = Runtime().FullInit(false, nil, 6)
    assert.NoError(t, err)
    Runtime().Destroy()

    err = Runtime().FullInit(false, nil, 0)
    assert.NoError(t, err)
    Runtime().Destroy()

    heap_buf := make([]byte, 128 * 1024)
    err = Runtime().FullInit(true, heap_buf, 4)
    assert.NoError(t, err)
    Runtime().Destroy()

    Runtime().FullInit(false, nil, 0)
    err = Runtime().FullInit(false, nil, 0)
    assert.NoError(t, err)
    Runtime().Destroy()
    Runtime().Destroy()
}
