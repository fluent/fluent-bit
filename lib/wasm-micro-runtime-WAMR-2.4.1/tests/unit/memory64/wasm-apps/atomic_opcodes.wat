(module
  ;; Memory definition: 4 GB = 65536
  ;;                    8 GB = 131072
  ;;                    16 GB = 262144
  ;;                    20 GB = 327680
  (memory (;0;) i64 200 200 shared)

  ;; Initialize memory with some values
  (data (i64.const 0) "\01\02\03\04\05\06\07\08\09\0A\0B\0C\0D\0E\0F\10")

  ;; Function to test i32.atomic.store with i64 address
  (func (export "i32_atomic_store") (param $addr i64) (param $value i32)
    (i32.atomic.store (local.get $addr) (local.get $value))
  )

  ;; Function to test i32.atomic.store8 with i64 address
  (func (export "i32_atomic_store8") (param $addr i64) (param $value i32)
    (i32.atomic.store8 (local.get $addr) (local.get $value))
  )

  ;; Function to test i32.atomic.store16 with i64 address
  (func (export "i32_atomic_store16") (param $addr i64) (param $value i32)
    (i32.atomic.store16 (local.get $addr) (local.get $value))
  )

  ;; Function to test i64.atomic.store with i64 address
  (func (export "i64_atomic_store") (param $addr i64) (param $value i64)
    (i64.atomic.store (local.get $addr) (local.get $value))
  )

  ;; Function to test i64.atomic.store8 with i64 address
  (func (export "i64_atomic_store8") (param $addr i64) (param $value i64)
    (i64.atomic.store8 (local.get $addr) (local.get $value))
  )

  ;; Function to test i64.atomic.store16 with i64 address
  (func (export "i64_atomic_store16") (param $addr i64) (param $value i64)
    (i64.atomic.store16 (local.get $addr) (local.get $value))
  )

  ;; Function to test i64.atomic.store32 with i64 address
  (func (export "i64_atomic_store32") (param $addr i64) (param $value i64)
    (i64.atomic.store32 (local.get $addr) (local.get $value))
  )

  ;; Function to test i32.atomic.load with i64 address
  (func (export "i32_atomic_load") (param $addr i64) (result i32)
    (i32.atomic.load (local.get $addr))
  )

  ;; Function to test i32.atomic.load8_u with i64 address
  (func (export "i32_atomic_load8_u") (param $addr i64) (result i32)
    (i32.atomic.load8_u (local.get $addr))
  )

  ;; Function to test i32.atomic.load16_u with i64 address
  (func (export "i32_atomic_load16_u") (param $addr i64) (result i32)
    (i32.atomic.load16_u (local.get $addr))
  )

  ;; Function to test i64.atomic.load with i64 address
  (func (export "i64_atomic_load") (param $addr i64) (result i64)
    (i64.atomic.load (local.get $addr))
  )

  ;; Function to test i64.atomic.load8_u with i64 address
  (func (export "i64_atomic_load8_u") (param $addr i64) (result i64)
    (i64.atomic.load8_u (local.get $addr))
  )

  ;; Function to test i64.atomic.load16_u with i64 address
  (func (export "i64_atomic_load16_u") (param $addr i64) (result i64)
    (i64.atomic.load16_u (local.get $addr))
  )

  ;; Function to test i64.atomic.load32_u with i64 address
  (func (export "i64_atomic_load32_u") (param $addr i64) (result i64)
    (i64.atomic.load32_u (local.get $addr))
  )

  ;; Function to test i32.atomic.rmw.add with i64 address
  (func (export "i32_atomic_rmw_add") (param $addr i64) (param $value i32) (result i32)
    (i32.atomic.rmw.add (local.get $addr) (local.get $value))
  )

  ;; Function to test i32.atomic.rmw8.add_u with i64 address
  (func (export "i32_atomic_rmw8_add_u") (param $addr i64) (param $value i32) (result i32)
    (i32.atomic.rmw8.add_u (local.get $addr) (local.get $value))
  )

  ;; Function to test i32.atomic.rmw16.add_u with i64 address
  (func (export "i32_atomic_rmw16_add_u") (param $addr i64) (param $value i32) (result i32)
    (i32.atomic.rmw16.add_u (local.get $addr) (local.get $value))
  )

  ;; Function to test i64.atomic.rmw.add with i64 address
  (func (export "i64_atomic_rmw_add") (param $addr i64) (param $value i64) (result i64)
    (i64.atomic.rmw.add (local.get $addr) (local.get $value))
  )

  ;; Function to test i64.atomic.rmw8.add_u with i64 address
  (func (export "i64_atomic_rmw8_add_u") (param $addr i64) (param $value i64) (result i64)
    (i64.atomic.rmw8.add_u (local.get $addr) (local.get $value))
  )

  ;; Function to test i64.atomic.rmw16.add_u with i64 address
  (func (export "i64_atomic_rmw16_add_u") (param $addr i64) (param $value i64) (result i64)
    (i64.atomic.rmw16.add_u (local.get $addr) (local.get $value))
  )

  ;; Function to test i64.atomic.rmw32.add_u with i64 address
  (func (export "i64_atomic_rmw32_add_u") (param $addr i64) (param $value i64) (result i64)
    (i64.atomic.rmw32.add_u (local.get $addr) (local.get $value))
  )

  (func (export "i64_atomic_rmw_cmpxchg") (param $addr i64) (param $old i64) (param $new i64) (result i64)
    (i64.atomic.rmw.cmpxchg (local.get $addr) (local.get $old) (local.get $new))
  )

)