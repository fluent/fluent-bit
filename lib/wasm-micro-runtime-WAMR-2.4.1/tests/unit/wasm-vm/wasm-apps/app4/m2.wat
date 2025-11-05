(module
  (import "m1" "f1" (func $m1-f1 (result i32)))
  (export "m1-f1" (func $m1-f1))

  (import "m1" "m1" (memory $m1-m1 1 2))
  (import "m1" "t1" (table $m1-t1 0 funcref))
  (import "m1" "g1" (global $m1-g1 i32))

  (func $f2 (export "f2") (param i32) (result i32)
    (i32.add (call $m1-f1) (local.get 0))
  )

  (func $f4 (result i32) (i32.const 3))

  (func $f3 (export "f3") (param i32 i32) (result i32)
    (i32.add
      (call $m1-f1)
      (i32.add
        (call $f4)
        (call $f2 (local.get 0))
      )
    )
  )
)