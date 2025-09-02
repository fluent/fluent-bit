(module
  (type $t (struct (field i32 (mut i32))))
  (func (export "struct.get-null")
    (local (ref null $t)) (drop (struct.get $t 1 (local.get 0)))
  )
  (func (export "struct.set-null")
    (local (ref null $t)) (struct.set $t 1 (local.get 0) (i32.const 0))
  )
)
