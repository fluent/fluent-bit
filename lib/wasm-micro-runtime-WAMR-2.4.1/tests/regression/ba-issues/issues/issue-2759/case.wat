(module
  (type (;0;) (func (param f64) (result f64)))
  (type (;1;) (func (param i32 i32 i32) (result i32)))
  (type (;2;) (func (param i32) (result i32)))
  (type (;3;) (func (param i32)))
  (type (;4;) (func (param i32 i32 i32)))
  (type (;5;) (func (param i32 i32) (result i32)))
  (type (;6;) (func (param i32 i64 i32) (result i64)))
  (type (;7;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;8;) (func))
  (import "wasi_snapshot_preview1" "args_sizes_get" (func (;0;) (type 5)))
  (import "wasi_snapshot_preview1" "args_get" (func (;1;) (type 5)))
  (import "wasi_snapshot_preview1" "proc_exit" (func (;2;) (type 3)))
  (import "wasi_snapshot_preview1" "fd_write" (func (;3;) (type 7)))
  (func (;4;) (type 8))
  (func (;5;) (type 4) (param i32 i32 i32))
  (func (;6;) (type 8)
    (local i32 i32 i32 i32 i32)
    block (result i32)  ;; label = @1
      loop  ;; label = @5
        local.get 4
        local.get 1
        i32.const 15720
        i32.add
        i32.store offset=15576
        
        i32.const 0
        i32.const 0
        i32.load offset=4
        i32.const 128
        i32.sub
        local.tee 0
        i32.store offset=4

        ;; i32.const 40
        ;; i32.load offset=28
        ;; call 2 ;; same here
        
        local.get 2
        i32.const 5
        local.get 3
        call 5

        i32.const 40
        i32.load offset=28
        call 2
        
        local.get 0
        i32.const 108
        i32.eq
        local.set 0
        local.get 1
        i32.const 34
        i32.eq
        local.set 0
        
        local.get 2
        i32.const 7
        local.get 3
        call 5
        
        local.get 4
        i32.const 1
        i32.add
        local.tee 4
        i32.const 36525
        i32.ne
        br_if 0 (;@5;)
      end
      i32.const 0
    end
    local.set 1
  )
  (table (;0;) 6 6 funcref)
  (memory (;0;) 8192 8192)
  (global (;0;) (mut i32) (i32.const 76368))
  (global (;1;) (mut i32) (i32.const 331012996))
  (global (;2;) (mut i64) (i64.const 575546917))
  (global (;3;) (mut f32) (f32.const 0x1.b8f31cp-34 (;=1.0026e-10;)))
  (global (;4;) (mut f64) (f64.const -0x1.8ae9ad59b18a9p-429 (;=-1.11274e-129;)))
  (export "memory" (memory 0))
  (export "_start" (func 6))
)