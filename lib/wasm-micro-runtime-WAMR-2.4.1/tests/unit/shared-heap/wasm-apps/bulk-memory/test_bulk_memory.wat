(module
  (memory 1)

  (func $memory_fill_test (param $dst i32) (param $val i32) (param $len i32)
    local.get $dst
    local.get $val
    local.get $len
    memory.fill
  )

  (export "memory_fill_test" (func $memory_fill_test))
)
