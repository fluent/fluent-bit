(module
  (type (;0;) (func))
  (type (;1;) (func (param i64 i64) (result i64 i64)))
  (func (;0;) (result i64)
    i64.const 230
    i64.const 366
    i64.div_u
    i64.const 968
    call 1
    i32.const 0
    if (param i64 i64) (result i64 i64)  ;; label = @1
    end
    i64.div_u
    ;; global.get 0
    ;; i64.add
    ;; global.set 0
    )
  (func (;1;) (type 1) (param i64 i64) (result i64 i64)
    i64.const 0
    i64.const 9223372036854775807)
  (global (;0;) (mut i64) (i64.const 853))
  (global (;1;) (mut f32) (f32.const 0x1.2f312cp+3 (;=9.47475;)))
  (export "_start" (func 0))
  (export "to_test" (func 0)))
