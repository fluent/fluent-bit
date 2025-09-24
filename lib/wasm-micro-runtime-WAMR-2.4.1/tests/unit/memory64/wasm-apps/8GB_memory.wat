(module
  ;; Memory definition: 4 GB = 65536
  ;;                    8 GB = 131072
  ;;                    16 GB = 262144
  ;;                    20 GB = 327680
  ;;                    32 GB = 524288
  (memory (;0;) i64 131072 131072)

  ;; if touch too many pages more than physical memory can provide, 
  ;; the signal will kill the process
  (func (export "touch_every_page") (result i64 i64 i32 i32)
    (local $i i64)
    i64.const 0x0000000000000ff8
    local.set $i 
    loop $loop
      ;; a[i] = i
      local.get $i
      local.get $i
      i64.store
      local.get $i 
      i64.const 4096
      i64.add 
      local.set $i 
      local.get $i
      ;; max boundary(exclusive) 8GB - 8 = 0x0000000200000000 - 8
      i64.const 0x0000000200000000 
      i64.const 8
      i64.sub
      i64.lt_u 
      br_if $loop
    end
    i64.const 0x000000000000fff8
    i64.load
    i64.const 0x000000010000fff8
    i64.load
    ;; lower 8 bytes of 0x000000010001fff8 -> 0x0001fff8
    i64.const 0x000000010001fff8
    i32.load
    ;; higher 8 bytes of 0x000000010001fff8 -> 0x1
    i64.const 0x000000010001fffc
    i32.load
    return 
  )

  ;; Function to test i64.atomic.store with i64 address
  (func (export "i64_store_offset_4GB") (param $addr i64) (param $value i64)
    (i64.store offset=0x100000000 (local.get $addr) (local.get $value))
  )

  (func (export "i64_load_offset_4GB") (param $addr i64) (result i64)
    (i64.load offset=0x100000000 (local.get $addr))
  )
)