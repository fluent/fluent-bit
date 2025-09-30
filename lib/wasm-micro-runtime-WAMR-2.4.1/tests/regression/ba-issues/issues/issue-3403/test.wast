(module
  (type (;0;) (func))
  (type (;1;) (func (result i64)))
  (type (;2;) (func (param i32 i32 i32) (result i32)))
  (func (;0;) (type 1) (result i64)
    i64.const 122
    i32.const 1
    i32.const 2147483647
    i32.const -1
    i32.const 1
    if (param i32 i32 i32) (result i32)  ;; label = @1
      select
    else
      br 0 (;@1;)
      nop
      select
    end
    drop
    )
  (export "_start" (func 0))
  (export "to_test" (func 0)))
