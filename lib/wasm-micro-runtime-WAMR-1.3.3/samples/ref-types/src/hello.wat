;; Copyright (C) 2019 Intel Corporation.  All rights reserved.
;; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

(module
  (type $t0 (func (param i32 externref) (result i32)))

  (import "env" "native-cmp-externref"
    (func $native-cmp-externref (param externref externref) (result i32))
  )

  (import "env" "native-chk-externref"
    (func $native-chk-externref (param i32 externref) (result i32))
  )

  (table $t1 8 8 externref)
  (table $t2 funcref
    (elem
      $native-cmp-externref
      $native-chk-externref
    )
  )

  (func (export "set-externref") (param $i i32) (param $r externref)
    (table.set $t1 (local.get $i) (local.get $r))
  )

  (func (export "get-externref") (param $i i32) (result externref)
    (table.get $t1 (local.get $i))
  )

  (func (export "cmp-externref") (param $i i32) (param $r externref) (result i32)
    (table.get $t1 (local.get $i))
    (local.get $r)
    (call $native-cmp-externref)
  )

  (func (export "chk-externref") (param $i i32) (param $r externref) (result i32)
    (call_indirect $t2 (type $t0)
      (local.get $i)
      (local.get $r)
      (i32.const 1)
    )
  )
)
