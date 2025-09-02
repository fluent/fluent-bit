(module
  (func $f1 (export "f1") (result i32) (i32.const 1))

  (memory $m1 1 2)
  (table $t1 0 funcref)
  (global $g1 i32 (i32.const 1))

  (export "m1" (memory $m1))
  (export "m1_alias" (memory $m1))
  (export "t1" (table $t1))
  (export "t1_alias" (table $t1))
  (export "g1" (global $g1))
  (export "g1_alias" (global $g1))
)