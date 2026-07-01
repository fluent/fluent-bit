;; Copyright (C) 2024 YAMAMOTO Takashi
;; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

(module
  (func $fd_read (import "wasi_snapshot_preview1" "fd_read") (param i32 i32 i32 i32) (result i32))
  (func $block_forever (export "block_forever")
    ;; read from FD 0
    i32.const 100 ;; iov_base
    i32.const 200 ;; buffer
    i32.store
    i32.const 104 ;; iov_len
    i32.const 1
    i32.store
    i32.const 0 ;; fd 0
    i32.const 100 ;; iov_base
    i32.const 1   ;; iov count
    i32.const 300 ;; retp (out)
    call $fd_read
    unreachable
  )
  (func (export "_start")
    call $block_forever
  )

  ;; a dumb malloc/free implementation
  (func (export "malloc") (param i32) (result i32)
    local.get 0
    i32.const 65535
    i32.add
    i32.const 65536
    i32.div_u
    memory.grow
    local.set 0
    local.get 0
    i32.const -1
    i32.eq
    if
      i32.const 0
      return
    end
    local.get 0
    i32.const 65536
    i32.mul
  )
  (func (export "free") (param i32))

  (memory (export "memory") 1)

  ;; fake globals to make wasm_set_aux_stack happy
  (global (export "__heap_base") i32 (i32.const 0x10000))
  (global (export "__data_end") i32 (i32.const 0x10000))
  (global (mut i32) (i32.const 0x10000))
)
