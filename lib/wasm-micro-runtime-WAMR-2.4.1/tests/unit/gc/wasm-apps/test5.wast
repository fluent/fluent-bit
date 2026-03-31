(module
  (type $t0 (sub (struct)))
  (type $t1 (sub $t0 (struct (field i32))))
  (type $t1' (sub $t0 (struct (field i32))))
  (type $t2 (sub $t1 (struct (field i32 i32))))
  (type $t2' (sub $t1' (struct (field i32 i32))))
  (type $t3 (sub $t0 (struct (field i32 i32))))
  (type $t0' (sub $t0 (struct)))
  (type $t4 (sub $t0' (struct (field i32 i32))))

  (table 20 (ref null struct))

  (func $init
    (table.set (i32.const 0) (struct.new_default $t0))
    (table.set (i32.const 10) (struct.new_default $t0))
    (table.set (i32.const 1) (struct.new_default $t1))
    (table.set (i32.const 11) (struct.new_default $t1'))
    (table.set (i32.const 2) (struct.new_default $t2))
    (table.set (i32.const 12) (struct.new_default $t2'))
    (table.set (i32.const 3) (struct.new_default $t3))
    (table.set (i32.const 4) (struct.new_default $t4))
  )

  (func (export "test-sub")
    (call $init)

    (drop (ref.cast (ref null $t0) (ref.null struct)))
    (drop (ref.cast (ref null $t0) (table.get (i32.const 0))))
    (drop (ref.cast (ref null $t0) (table.get (i32.const 1))))
    (drop (ref.cast (ref null $t0) (table.get (i32.const 2))))
    (drop (ref.cast (ref null $t0) (table.get (i32.const 3))))
    (drop (ref.cast (ref null $t0) (table.get (i32.const 4))))

    (drop (ref.cast (ref null $t0) (ref.null struct)))
    (drop (ref.cast (ref null $t1) (table.get (i32.const 1))))
    (drop (ref.cast (ref null $t1) (table.get (i32.const 2))))

    (drop (ref.cast (ref null $t0) (ref.null struct)))
    (drop (ref.cast (ref null $t2) (table.get (i32.const 2))))

    (drop (ref.cast (ref null $t0) (ref.null struct)))
    (drop (ref.cast (ref null $t3) (table.get (i32.const 3))))

    (drop (ref.cast (ref null $t4) (table.get (i32.const 4))))

    (drop (ref.cast (ref $t0) (table.get (i32.const 0))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 1))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 2))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 3))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 4))))

    (drop (ref.cast (ref $t1) (table.get (i32.const 1))))
    (drop (ref.cast (ref $t1) (table.get (i32.const 2))))

    (drop (ref.cast (ref $t2) (table.get (i32.const 2))))

    (drop (ref.cast (ref $t3) (table.get (i32.const 3))))

    (drop (ref.cast (ref $t4) (table.get (i32.const 4))))
  )

  (func (export "test-canon")
    (call $init)

    (drop (ref.cast (ref $t0) (table.get (i32.const 0))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 1))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 2))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 3))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 4))))

    (drop (ref.cast (ref $t0) (table.get (i32.const 10))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 11))))
    (drop (ref.cast (ref $t0) (table.get (i32.const 12))))

    (drop (ref.cast (ref $t1') (table.get (i32.const 1))))
    (drop (ref.cast (ref $t1') (table.get (i32.const 2))))

    (drop (ref.cast (ref $t1) (table.get (i32.const 11))))
    (drop (ref.cast (ref $t1) (table.get (i32.const 12))))

    (drop (ref.cast (ref $t2') (table.get (i32.const 2))))

    (drop (ref.cast (ref $t2) (table.get (i32.const 12))))
  )
)
