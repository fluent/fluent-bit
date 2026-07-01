(module
  (type $0 (func (result i32)))
  (type $1 (func (param i32) (result i32)))
  (memory 1)
  (export "mem_grow" (func $6))
  (export "mem_size" (func $7))
 
  (func $6 (type $1) (param $0 i32) (result i32)
    local.get $0
    memory.grow
    )

  (func $7 (type $0) (result i32)
    memory.size
    )
)
