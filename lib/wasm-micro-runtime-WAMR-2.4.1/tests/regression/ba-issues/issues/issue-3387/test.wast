(module
  (type (;0;) (func))
  (type (;1;) (func (result i32)))
  (type (;2;) (func (param f32) (result f32)))
  (func (;0;)  (result i64)
    i32.const -1518330408
    i64.const 1022
    i64.const 904
    i64.add
    global.get 0
    i64.add
    global.set 0
    f32.const 0x1.01499cp+1 (;=2.01006;)
    call 1
    i32.const 0
    if (param f32) (result f32)  ;; label = @1
    end
    i64.trunc_f32_u
    return
    )
  (func (;1;) (type 2) (param f32) (result f32)
    f32.const inf (;=inf;))
  (global (;0;) (mut i64) (i64.const 858))
  (global (;1;) (mut f64) (f64.const 0x1.0370499c98398p+3 (;=8.10746;)))
  (export "_start" (func 0))
  (export "to_test" (func 0))
)
