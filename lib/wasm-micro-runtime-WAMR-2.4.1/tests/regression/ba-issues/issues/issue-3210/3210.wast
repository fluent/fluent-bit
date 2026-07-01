(module
  (type $0 (func (result i32)))
  (type $1 (func (param f64 f64 i32 f64 f32) (result i32)))
  (memory $3  1)
  (table $2  2 funcref)
  (global $4  (mut f64) (f64.const -0x1.0035c4524daf8p+7))
  (export "_main" (func $6))
  (elem $5 (i32.const 0)
    $7 $8)
  
  (func $6 (type $0)
    (result i32)
    (local $0 i32)
    (local $1 i64)
    (local $2 f32)
    (local $3 f64)
    i32.const 385
    f64.const 0x1.9cbe6f8f163aap+9
    f64.store offset=39 align=2
    f64.const 0x1.4530cd2e8aa6bp+8
    i32.const 702
    f64.load offset=12 align=2
    local.tee $3
    local.get $3
    i64.reinterpret_f64
    i64.const 9218868437227405312
    i64.and
    i64.popcnt
    i64.const 11
    i64.eq
    select
    local.tee $3
    global.get $4
    i32.const 440
    i32.load16_u offset=58 align=1
    i32.const 178
    i32.load offset=16 align=2
    i32.and
    global.get $4
    f64.const 0x1.abf60cf2b5ea8p+8
    i32.const 554
    f64.load offset=74 align=1
    local.tee $3
    local.get $3
    i64.reinterpret_f64
    i64.const 9218868437227405312
    i64.and
    i64.popcnt
    i64.const 11
    i64.eq
    select
    local.tee $3
    f64.min
    i32.const 758
    i32.load16_u offset=35 align=1
    i32.const 334
    i32.load16_s offset=81 align=1
    br_if 0
    drop
    f32.const 0x1.bbacd6p+9
    i32.const 1
    call_indirect $2 (type $1)
    )
  
  (func $7 (type $0)
    (result i32)
    i32.const 0
    )
  
  (func $8 (type $1)
    (param $0 f64)
    (param $1 f64)
    (param $2 i32)
    (param $3 f64)
    (param $4 f32)
    (result i32)
    (local $5 i32)
    (local $6 i64)
    (local $7 f32)
    (local $8 f64)
    (local $9 i32)
    (local $10 i32)
    i32.const 86
    local.set $10
    i32.const 684
    i32.load8_s offset=77
    local.tee $2
    i32.const 0
    call_indirect $2 (type $0)
    i32.xor
    local.set $9
    loop $loop
      local.get $9
      i32.const 561
      i64.load offset=74 align=4
      i32.const 183
      i64.load offset=94 align=2
      i64.eq
      i32.add
      local.set $9
      local.get $10
      i32.const -1
      i32.add
      local.tee $10
      br_if $loop
    end ;; $loop
    local.get $9
    local.get $2
    i32.extend8_s
    i32.rotr
    ))