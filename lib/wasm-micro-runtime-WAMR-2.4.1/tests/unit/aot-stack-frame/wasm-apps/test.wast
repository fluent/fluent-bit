(module
  (func $test1 (export "test1") (param i32 i32) (result i32)
    i32.const 0x11223344
    i64.const 0x1234_5678_ABCD_EF99
    f32.const 5566.7788
    f64.const 99887766.55443322
    unreachable
  )

  (func $test2 (export "test2") (param f32 f32) (result i32)
    i32.const 0x11223344
    i64.const 0x1234_5678_ABCD_EF99
    f32.const 5566.7788
    f64.const 99887766.55443322

    loop
      i32.const 0x1234
      i32.const 0x5678
      unreachable
    end

    unreachable
  )

  (func $test3 (export "test3") (param i32 i32) (result i32)
    i32.const 0x11223344
    i64.const 0x1234_5678_ABCD_EF99

    i32.const 0x1234
    i32.const 0x5678
    call $test1

    drop
    drop
  )
)
