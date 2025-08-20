;; Copyright (C) 2019 Intel Corporation.  All rights reserved.
;; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

(module
  (func $get_pairs (import "" "get_pairs") (result i32))
  (func $log (import "" "log") (param i32 i32))

  (func $on_start (export "on_start")
    (call $log (i32.const 0) (i32.const 9))
    (call $get_pairs)
    (drop)
  )

  (func $on_stop (export "on_stop")
    (call $log (i32.const 9) (i32.const 8))
  )

  (func $malloc (export "malloc") (param i32) (result i32)
    (call $log (i32.const 17) (i32.const 7))
    (i32.const 64)
  )

  (func $free(export "free") (param i32)
    (call $log (i32.const 24) (i32.const 5))
  )

  (memory (export "memory") 1)
  (data (i32.const 0) "on_start")
  (data (i32.const 9) "on_stop")
  (data (i32.const 17) "malloc")
  (data (i32.const 24) "free")
)
