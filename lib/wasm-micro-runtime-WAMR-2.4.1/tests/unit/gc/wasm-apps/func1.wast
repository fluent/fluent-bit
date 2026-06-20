(module
  (type $t (func))

  (func (export "test") (param structref i31ref)
    (local funcref)
    (local funcref)
    (local funcref)
    (local externref)
    (local externref)
    (local externref)
    (local anyref)
    (local eqref)
    (local structref)
    (local arrayref)
    (local i31ref)
    (local (ref null 0))
    (local (ref null 0))
    (local (ref null 0))
    (local (ref null 1))
    (local (ref null func))
    (local (ref null 0))
    (local (ref null extern))
    (local (ref null any))
    (local (ref null eq))
    (local (ref null i31))
    (local (ref null struct))

    local.get 0
    ref.test (ref array)
    drop
    local.get 1
    ref.cast (ref i31)
    drop
  )
)
