(module
  (type (func))
  (type (func (param i32 i32) (result i32)))
  (type (func (param i32)))
  (import "wasi_snapshot_preview1" "sock_shutdown" (func $sock_shutdown (type 1)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (type 2)))
  (func $_start
    (call $sock_shutdown
      (i32.const 3)
      (i32.const 3)
    )
    call $proc_exit
  )
  (memory 2)
  (export "memory" (memory 0))
  (export "_start" (func $_start))
)