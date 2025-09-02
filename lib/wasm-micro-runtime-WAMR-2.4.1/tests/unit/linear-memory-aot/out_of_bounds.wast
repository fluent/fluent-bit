(module
  (type $1 (func (param i32) (result i32)))
  (memory $3 0)
  (export "load" (func $4))

  (func $4 (type $1) (param $0 i32) (result i32)
    local.get $0
    i32.load
    )
)
