;; Copyright (C) 2023 Midokura Japan KK.  All rights reserved.
;; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

(module
  (func (export "test_data_drop") (result i32)
    (memory.init 0 (i32.const 0) (i32.const 0) (i32.const 4))
    data.drop 0
    (i32.load (i32.const 0))
  )
  (func (export "test_elem_drop") (result i32)
    (table.init 0 (i32.const 0) (i32.const 0) (i32.const 4))
    elem.drop 0
    i32.const 3
    table.get 0
    ref.is_null
  )
  (func $f)
  (memory 1 1)
  (table 4 4 funcref)
  (data "abcd")
  (elem func $f $f $f $f)
)
