(module
  (type $0 (func (param i32) (result i32)))
  (type $1 (func (param i32 i32) (result i32)))
  (type $2 (func (param i32)))
  (type $3 (func (param i32 i32 i32) (result i32)))
  (type $4 (func))
  (type $5 (func (result i32)))
  (import "env" "malloc" (func $13 (param i32) (result i32)))
  (import "env" "calloc" (func $14 (param i32 i32) (result i32)))
  (import "env" "free" (func $15 (param i32)))
  (import "env" "memcpy" (func $16 (param i32 i32 i32) (result i32)))
  (import "env" "strdup" (func $17 (param i32) (result i32)))
  (memory $6  1)
  (global $7  i32 (i32.const 1024))
  (global $8  i32 (i32.const 1024))
  (global $9  i32 (i32.const 1024))
  (global $10  i32 (i32.const 5120))
  (global $11  i32 (i32.const 0))
  (global $12  i32 (i32.const 1))
  (export "memory" (memory $6))
  (export "__wasm_call_ctors" (func $18))
  (export "on_init" (func $18))
  (export "my_sqrt" (func $19))
  (export "null_pointer" (func $20))
  (export "my_malloc" (func $21))
  (export "my_calloc" (func $22))
  (export "my_free" (func $23))
  (export "my_memcpy" (func $24))
  (export "my_strdup" (func $25))
  (export "__dso_handle" (global $7))
  (export "__data_end" (global $8))
  (export "__global_base" (global $9))
  (export "__heap_base" (global $10))
  (export "__memory_base" (global $11))
  (export "__table_base" (global $12))
  
  (func $18 (type $4)
    nop
    )
  
  (func $19 (type $1)
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
  
  (func $20 (type $5)
    (result i32)
    i32.const 0
    )
  
  (func $21 (type $0)
    (param $0 i32)
    (result i32)
    local.get $0
    call $13
    )
  
  (func $22 (type $1)
    (param $0 i32)
    (param $1 i32)
    (result i32)
    local.get $0
    local.get $1
    call $14
    )
  
  (func $23 (type $2)
    (param $0 i32)
    local.get $0
    call $15
    )
  
  (func $24 (type $3)
    (param $0 i32)
    (param $1 i32)
    (param $2 i32)
    (result i32)
    local.get $0
    local.get $1
    local.get $2
    call $16
    )
  
  (func $25 (type $0)
    (param $0 i32)
    (result i32)
    local.get $0
    call $17
    )
  
  ;;(custom_section "producers"
  ;;  (after code)
  ;;  "\01\0cprocessed-by\01\05clangV11.0.0 (ht"
  ;;  "tps://github.com/llvm/llvm-proje"
  ;;  "ct 176249bd6732a8044d457092ed932"
  ;;  "768724a6f06)")
  
  )