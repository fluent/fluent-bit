(module
  (import "m1" "f1" (func $m1-f1 (result i32)))
  (import "m1" "m1_alias" (memory $m1-m1 1 2))
  (import "m1" "t1_alias" (table $m1-t1 0 funcref))
  (import "m1" "g1_alias" (global $m1-g1 i32))
  (import "m2" "f2" (func $m2-f2 (param i32) (result i32)))
)