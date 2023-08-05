;; Copyright (C) 2019 Intel Corporation.  All rights reserved.
;; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

(module
  (global $mut_f32_import (export "var f32") (import "globalexportimport-0" "var f32") (mut f32))
  (func (export "get var f32 export") (import "globalexportimport-0" "get var f32 export") (result f32))
  (func (export "set var f32 export") (import "globalexportimport-0" "set var f32 export") (param f32))
  (func (export "get var f32 import") (result f32) (global.get $mut_f32_import))
  (func (export "set var f32 import") (param f32) (global.set $mut_f32_import (local.get 0)))
)