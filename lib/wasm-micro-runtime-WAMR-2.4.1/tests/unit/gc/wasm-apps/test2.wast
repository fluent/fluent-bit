(module
  (type $ft (func))
  (type $st (struct))
  (type $at (array i8))

  (table $ta 10 anyref)
  (table $tf 10 funcref)
  (table $te 10 externref)

  (elem declare func $f)
  (func $f)

  (func (export "init") (param $x externref)
    (table.set $ta (i32.const 0) (ref.null any))
    (table.set $ta (i32.const 1) (ref.null struct))
    (table.set $ta (i32.const 2) (ref.null none))
    (table.set $ta (i32.const 3) (ref.i31 (i32.const 7)))
    (table.set $ta (i32.const 4) (struct.new_default $st))
    (table.set $ta (i32.const 5) (array.new_default $at (i32.const 0)))
    (table.set $ta (i32.const 6) (any.convert_extern (local.get $x)))
    (table.set $ta (i32.const 7) (any.convert_extern (ref.null extern)))

    (table.set $tf (i32.const 0) (ref.null nofunc))
    (table.set $tf (i32.const 1) (ref.null func))
    (table.set $tf (i32.const 2) (ref.func $f))

    (table.set $te (i32.const 0) (ref.null noextern))
    (table.set $te (i32.const 1) (ref.null extern))
    (table.set $te (i32.const 2) (local.get $x))
    (table.set $te (i32.const 3) (extern.convert_any (ref.i31 (i32.const 8))))
    (table.set $te (i32.const 4) (extern.convert_any (struct.new_default $st)))
    (table.set $te (i32.const 5) (extern.convert_any (ref.null any)))
  )

  (func (export "ref_test_null_data") (param $i i32) (result i32)
    (i32.add
      (ref.is_null (table.get $ta (local.get $i)))
      (ref.test nullref (table.get $ta (local.get $i)))
    )
  )
  (func (export "ref_test_any") (param $i i32) (result i32)
    (i32.add
      (ref.test (ref any) (table.get $ta (local.get $i)))
      (ref.test anyref (table.get $ta (local.get $i)))
    )
  )
  (func (export "ref_test_eq") (param $i i32) (result i32)
    (i32.add
      (ref.test (ref eq) (table.get $ta (local.get $i)))
      (ref.test eqref (table.get $ta (local.get $i)))
    )
  )
  (func (export "ref_test_i31") (param $i i32) (result i32)
    (i32.add
      (ref.test (ref i31) (table.get $ta (local.get $i)))
      (ref.test i31ref (table.get $ta (local.get $i)))
    )
  )
  (func (export "ref_test_struct") (param $i i32) (result i32)
    (i32.add
      (ref.test (ref struct) (table.get $ta (local.get $i)))
      (ref.test structref (table.get $ta (local.get $i)))
    )
  )
  (func (export "ref_test_array") (param $i i32) (result i32)
    (i32.add
      (ref.test (ref array) (table.get $ta (local.get $i)))
      (ref.test arrayref (table.get $ta (local.get $i)))
    )
  )

  (func (export "ref_test_null_func") (param $i i32) (result i32)
    (i32.add
      (ref.is_null (table.get $tf (local.get $i)))
      (ref.test (ref null nofunc) (table.get $tf (local.get $i)))
    )
  )
  (func (export "ref_test_func") (param $i i32) (result i32)
    (i32.add
      (ref.test (ref func) (table.get $tf (local.get $i)))
      (ref.test funcref (table.get $tf (local.get $i)))
    )
  )

  (func (export "ref_test_null_extern") (param $i i32) (result i32)
    (i32.add
      (ref.is_null (table.get $te (local.get $i)))
      (ref.test (ref null noextern) (table.get $te (local.get $i)))
    )
  )
  (func (export "ref_test_extern") (param $i i32) (result i32)
    (i32.add
      (ref.test (ref extern) (table.get $te (local.get $i)))
      (ref.test externref (table.get $te (local.get $i)))
    )
  )
)
