(module
  (type $0 (func (param i32 i32 i32) (result i32)))
  (type $1 (func (param i32 i32) (result i32)))
  (type $2 (func (param i32) (result i32)))
  (type $3 (func (param i32)))
  (type $4 (func (param i32 i32 i32 i32) (result i32)))
  (type $5 (func))
  (type $6 (func (result i32)))
  (import "env" "malloc" (func $15 (param i32) (result i32)))
  (import "env" "calloc" (func $16 (param i32 i32) (result i32)))
  (import "env" "free" (func $17 (param i32)))
  (import "env" "memcpy" (func $18 (param i32 i32 i32) (result i32)))
  (import "env" "strdup" (func $19 (param i32) (result i32)))
  (import "env" "memcmp" (func $20 (param i32 i32 i32) (result i32)))
  (import "env" "printf" (func $21 (param i32 i32) (result i32)))
  (import "env" "sprintf" (func $22 (param i32 i32 i32) (result i32)))
  (import "env" "snprintf" (func $23 (param i32 i32 i32 i32) (result i32)))
  (import "env" "puts" (func $24 (param i32) (result i32)))
  (import "env" "putchar" (func $25 (param i32) (result i32)))
  (import "env" "memmove" (func $26 (param i32 i32 i32) (result i32)))
  (import "env" "memset" (func $27 (param i32 i32 i32) (result i32)))
  (import "env" "strchr" (func $28 (param i32 i32) (result i32)))
  (import "env" "strcmp" (func $29 (param i32 i32) (result i32)))
  (import "env" "strcpy" (func $30 (param i32 i32) (result i32)))
  (import "env" "strlen" (func $31 (param i32) (result i32)))
  (import "env" "strncmp" (func $32 (param i32 i32 i32) (result i32)))
  (import "env" "strncpy" (func $33 (param i32 i32 i32) (result i32)))
  (memory $7  1)
  (global $8  (mut i32) (i32.const 5120))
  (global $9  i32 (i32.const 1024))
  (global $10  i32 (i32.const 1024))
  (global $11  i32 (i32.const 1024))
  (global $12  i32 (i32.const 5120))
  (global $13  i32 (i32.const 0))
  (global $14  i32 (i32.const 1))
  (export "memory" (memory $7))
  (export "__wasm_call_ctors" (func $34))
  (export "on_init" (func $34))
  (export "my_sqrt" (func $35))
  (export "null_pointer" (func $36))
  (export "my_malloc" (func $37))
  (export "my_calloc" (func $38))
  (export "my_free" (func $39))
  (export "my_memcpy" (func $40))
  (export "my_strdup" (func $41))
  (export "my_memcmp" (func $42))
  (export "my_printf" (func $43))
  (export "my_sprintf" (func $44))
  (export "my_snprintf" (func $45))
  (export "my_puts" (func $46))
  (export "my_putchar" (func $47))
  (export "my_memmove" (func $48))
  (export "my_memset" (func $49))
  (export "my_strchr" (func $50))
  (export "my_strcmp" (func $51))
  (export "my_strcpy" (func $52))
  (export "my_strlen" (func $53))
  (export "my_strncmp" (func $54))
  (export "my_strncpy" (func $55))
  (export "__dso_handle" (global $9))
  (export "__data_end" (global $10))
  (export "__global_base" (global $11))
  (export "__heap_base" (global $12))
  (export "__memory_base" (global $13))
  (export "__table_base" (global $14))
  
  (func $34 (type $5)
    nop
    )
  
  (func $35 (type $1)
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
  
  (func $36 (type $6)
    (result i32)
    i32.const 0
    )
  
  (func $37 (type $2)
    (param $0 i32)
    (result i32)
    local.get $0
    call $15
    )
  
  (func $38 (type $1)
    (param $0 i32)
    (param $1 i32)
    (result i32)
    local.get $0
    local.get $1
    call $16
    )
  
  (func $39 (type $3)
    (param $0 i32)
    local.get $0
    call $17
    )
  
  (func $40 (type $0)
    (param $0 i32)
    (param $1 i32)
    (param $2 i32)
    (result i32)
    local.get $0
    local.get $1
    local.get $2
    call $18
    )
  
  (func $41 (type $2)
    (param $0 i32)
    (result i32)
    local.get $0
    call $19
    )
  
  (func $42 (type $0)
    (param $0 i32)
    (param $1 i32)
    (param $2 i32)
    (result i32)
    local.get $0
    local.get $1
    local.get $2
    call $20
    )
  
  (func $43 (type $1)
    (param $0 i32)
    (param $1 i32)
    (result i32)
    (local $2 i32)
    global.get $8
    i32.const 16
    i32.sub
    local.tee $2
    global.set $8
    local.get $2
    local.get $1
    i32.store
    local.get $0
    local.get $2
    call $21
    local.get $2
    i32.const 16
    i32.add
    global.set $8
    )
  
  (func $44 (type $0)
    (param $0 i32)
    (param $1 i32)
    (param $2 i32)
    (result i32)
    (local $3 i32)
    global.get $8
    i32.const 16
    i32.sub
    local.tee $3
    global.set $8
    local.get $3
    local.get $2
    i32.store
    local.get $0
    local.get $1
    local.get $3
    call $22
    local.get $3
    i32.const 16
    i32.add
    global.set $8
    )
  
  (func $45 (type $4)
    (param $0 i32)
    (param $1 i32)
    (param $2 i32)
    (param $3 i32)
    (result i32)
    (local $4 i32)
    global.get $8
    i32.const 16
    i32.sub
    local.tee $4
    global.set $8
    local.get $4
    local.get $3
    i32.store
    local.get $0
    local.get $1
    local.get $2
    local.get $4
    call $23
    local.get $4
    i32.const 16
    i32.add
    global.set $8
    )
  
  (func $46 (type $2)
    (param $0 i32)
    (result i32)
    local.get $0
    call $24
    )
  
  (func $47 (type $2)
    (param $0 i32)
    (result i32)
    local.get $0
    call $25
    )
  
  (func $48 (type $0)
    (param $0 i32)
    (param $1 i32)
    (param $2 i32)
    (result i32)
    local.get $0
    local.get $1
    local.get $2
    call $26
    )
  
  (func $49 (type $0)
    (param $0 i32)
    (param $1 i32)
    (param $2 i32)
    (result i32)
    local.get $0
    local.get $1
    local.get $2
    call $27
    )
  
  (func $50 (type $1)
    (param $0 i32)
    (param $1 i32)
    (result i32)
    local.get $0
    local.get $1
    call $28
    )
  
  (func $51 (type $1)
    (param $0 i32)
    (param $1 i32)
    (result i32)
    local.get $0
    local.get $1
    call $29
    )
  
  (func $52 (type $1)
    (param $0 i32)
    (param $1 i32)
    (result i32)
    local.get $0
    local.get $1
    call $30
    )
  
  (func $53 (type $2)
    (param $0 i32)
    (result i32)
    local.get $0
    call $31
    )
  
  (func $54 (type $0)
    (param $0 i32)
    (param $1 i32)
    (param $2 i32)
    (result i32)
    local.get $0
    local.get $1
    local.get $2
    call $32
    )
  
  (func $55 (type $0)
    (param $0 i32)
    (param $1 i32)
    (param $2 i32)
    (result i32)
    local.get $0
    local.get $1
    local.get $2
    call $33
    )
  
  ;;(custom_section "producers"
  ;;  (after code)
  ;;  "\01\0cprocessed-by\01\05clangV11.0.0 (ht"
  ;;  "tps://github.com/llvm/llvm-proje"
  ;;  "ct 176249bd6732a8044d457092ed932"
  ;;  "768724a6f06)")
  
  )