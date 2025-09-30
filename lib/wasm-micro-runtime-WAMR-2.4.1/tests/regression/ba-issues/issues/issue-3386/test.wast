(module
  (type $0 (func))
  (type $1 (func (result i32)))
  (type $2 (func (param i32 i32) (result i32 i32)))
  (export "_start" (func $3))
  (export "to_test" (func $3))
  
  (func $3 (type $1)
    (result i32)
    f32.const -0x1.0bb6d6p+2
    f32.const -0x1.2a640ap+2
    f32.ge
    i32.const 353
    call $4
    i32.const 1
    if $if (param i32 i32) (result i32 i32)
    end ;; $if
    i32.gt_u
    return
    )
  
  (func $4 (type $2)
    (param $0 i32)
    (param $1 i32)
    (result i32 i32)
    i32.const -1
    i32.const 2147483647
    ))
