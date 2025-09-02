(module
  (type (func))
  (func $_start
    (memory.grow (i32.const 1))
    drop
    (memory.fill (i32.const 65536) (i32.const 0) (i32.const 10))
  )
  (memory 1)
  (export "memory" (memory 0))
  (export "_start" (func $_start))
)