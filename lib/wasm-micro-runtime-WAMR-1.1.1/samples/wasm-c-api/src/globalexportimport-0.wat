;; Copyright (C) 2019 Intel Corporation.  All rights reserved.
;; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

(module
  (global $mut_f32_export (export "var f32") (mut f32) (f32.const 7))
  (func (export "get var f32 export") (result f32) (global.get $mut_f32_export))
  (func (export "set var f32 export") (param f32) (global.set $mut_f32_export (local.get 0)))
)
