/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _MODULE_CONFIG_H_
#define _MODULE_CONFIG_H_

#define ENABLE_MODULE_JEFF 0
#define ENABLE_MODULE_WASM_APP 1
#define ENABLE_MODULE_WASM_LIB 1

#ifdef ENABLE_MODULE_JEFF
#include "module_jeff.h"
#endif
#ifdef ENABLE_MODULE_WASM_APP
#include "module_wasm_app.h"
#endif
#ifdef ENABLE_MODULE_WASM_LIB
#include "module_wasm_lib.h"
#endif

#endif /* _MODULE_CONFIG_H_ */
