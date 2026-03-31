(module
    (func $report (import "" "report") (param i32))

    (memory (export "mem") 1 1)

    (func $wasm_set_byte (export "set_byte") (param i32 i32)
        (call $report (i32.const 1))
        (i32.store8 (local.get 0) (local.get 1))
    )

    (func $wasm_get_byte (export "get_byte") (param i32) (result i32)
        (call $report (i32.const 2))
        (i32.load(local.get 0))
    )
)