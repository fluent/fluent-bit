(module
  (type $0 (func (param i32) (result i32)))
  (type $1 (func))
  (type $2 (func (result i32)))
  (type $3 (func (param i32 i32) (result i32)))
  (import "env" "malloc" (func $11 (param i32) (result i32)))
  (memory $4  1)
  (global $5  i32 (i32.const 1024))
  (global $6  i32 (i32.const 1024))
  (global $7  i32 (i32.const 1024))
  (global $8  i32 (i32.const 5120))
  (global $9  i32 (i32.const 0))
  (global $10  i32 (i32.const 1))
  (export "memory" (memory $4))
  (export "__wasm_call_ctors" (func $12))
  (export "on_init" (func $12))
  (export "my_sqrt" (func $13))
  (export "null_pointer" (func $14))
  (export "my_malloc" (func $15))
  (export "__dso_handle" (global $5))
  (export "__data_end" (global $6))
  (export "__global_base" (global $7))
  (export "__heap_base" (global $8))
  (export "__memory_base" (global $9))
  (export "__table_base" (global $10))
  
  (func $12 (type $1)
    nop
    )
  
  (func $13 (type $3)
    (param $0 i32)
    (param $1 i32)
    (result i32)
    local.get $1
    local.get $1
    i32.mul
    local.get $0
    local.get $0
    i32.mul
    i32.add
    )
  
  (func $14 (type $2)
    (result i32)
    i32.const 0
    )
  
  (func $15 (type $0)
    (param $0 i32)
    (result i32)
    local.get $0
    call $11
    )
  
  ;;(custom_section "producers"
  ;;  (after code)
  ;;  "\01\0cprocessed-by\01\05clangV11.0.0 (ht"
  ;;  "tps://github.com/llvm/llvm-proje"
  ;;  "ct 176249bd6732a8044d457092ed932"
  ;;  "768724a6f06)")
  
  )