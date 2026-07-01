(module
  (type $0 (func))
  (type $1 (func (param f32 f32) (result f32)))
  (type $2 (func (param i64 i64) (result i64)))
  (memory $4  1)
  (table $3  16 funcref)
  (export "main" (func $5))
  
  (func $5 (type $0)
    (local $0 f32)
    (local $1 i32)
    (local $2 i64)
    i32.const 1
    if $if
      local.get $0
      drop
      block $block (result i64)
        loop $loop (result i64)
          block $block_0 (result i64)
            i64.const 9223372036854775807
            i64.const 4304854250827437017
            call $7
            local.get $0
            i64.trunc_sat_f32_s
            i64.const 9223372036854775807
            i64.const 4304854250827437017
            call $7
            local.get $0
            unreachable
            nop
            unreachable
            local.get $1
            local.tee $1
            select
            local.get $1
            br_table
              $block_0
              $block_0 ;; default
          end ;; $block_0
        end ;; $loop
      end ;; $block
      local.set $2
    else
      i32.const 1
      local.set $1
    end ;; $if
    )
  
  (func $6 (type $1)
    (param $0 f32)
    (param $1 f32)
    (result f32)
    local.get $0
    local.get $1
    f32.max
    )
  
  (func $7 (type $2)
    (param $0 i64)
    (param $1 i64)
    (result i64)
    local.get $1
    f64.convert_i64_u
    i64.trunc_sat_f64_u
    i64.const 9223372036854775807
    i64.and
    ))