(module
  (type $t (func))
  (type $t0 (func (param (ref null $t) (ref $t) (ref null 0) (ref 0) (ref null 1) (ref 1))))
  (type $t1 (func (param funcref externref anyref eqref
                         i31ref structref arrayref
                         nullref nullfuncref nullexternref
                         (ref null func) (ref null extern) (ref null any) (ref null eq)
                         (ref null i31) (ref null struct) (ref null array)
                         (ref null none) (ref null nofunc) (ref null noextern)
                         (ref func) (ref extern) (ref any) (ref eq)
                         (ref i31) (ref struct) (ref array)
                         (ref none) (ref nofunc) (ref noextern)

                         (ref null 0) (ref null $t0) (ref null $t1)
                         (ref null func) (ref null extern) (ref null any) (ref null eq)
                         (ref null i31) (ref null struct) (ref null array)
                         (ref $t) (ref $t0) (ref $t1)
                         (ref func) (ref extern) (ref any) (ref eq)
                         (ref i31) (ref struct) (ref array))
                  (result (ref null func) (ref null extern) (ref $t0))))
  (type $t2 (func (param i32 i32) (result (ref null $t1))))

  ;; Duplicated types
  (type $t3 (func))
  (type $t4 (func (param (ref null $t) (ref $t) (ref null 0) (ref 0) (ref null 1) (ref 1))))
  (type $t5 (func (param funcref externref anyref eqref
                         i31ref structref arrayref
                         nullref nullfuncref nullexternref
                         (ref null func) (ref null extern) (ref null any) (ref null eq)
                         (ref null i31) (ref null struct) (ref null array)
                         (ref null none) (ref null nofunc) (ref null noextern)
                         (ref func) (ref extern) (ref any) (ref eq)
                         (ref i31) (ref struct) (ref array)
                         (ref none) (ref nofunc) (ref noextern)

                         (ref null 0) (ref null $t0) (ref null $t1)
                         (ref null func) (ref null extern) (ref null any) (ref null eq)
                         (ref null i31) (ref null struct) (ref null array)
                         (ref $t) (ref $t0) (ref $t1)
                         (ref func) (ref extern) (ref any) (ref eq)
                         (ref i31) (ref struct) (ref array))
                  (result (ref null func) (ref null extern) (ref $t0))))
  (type $t6 (func (param i32 i32) (result (ref null $t1))))

  (type (struct (field i8 (mut i16) (mut i32) i64 f32 f64
                       funcref externref (ref func) (ref extern)
                       anyref eqref structref arrayref i31ref
                       (ref null 0) (ref null 2) (ref null func) (ref null extern)
                       (ref null any) (ref null eq) (ref null i31) (ref null struct) (ref null array)
                       (ref 0) (ref $t0) (ref 3) (ref $t0) (ref null func)
                       (ref null extern) (ref null 5) (ref null $t0))))

  (type (struct))
  (type (struct (field)))
  (type (struct (field i8)))
  (type (struct (field i8 i8 i8 i8)))
  (type (struct (field $x1 i32) (field $y1 i32)))
  (type (struct (field i8 i16 i32 i64 f32 f64 anyref funcref (ref 0) (ref null 1))))
  (type (struct (field i32 i64 i8) (field) (field) (field (ref null i31) anyref)))
  (type (struct (field $x2 i32) (field f32 f64) (field $y2 i32)))

  ;; Duplicated types
  (type (struct (field i8 (mut i16) (mut i32) i64 f32 f64
                       funcref externref (ref func) (ref extern)
                       anyref eqref structref arrayref i31ref
                       (ref null 0) (ref null 2) (ref null func) (ref null extern)
                       (ref null any) (ref null eq) (ref null i31) (ref null struct) (ref null array)
                       (ref 0) (ref $t0) (ref 3) (ref $t0) (ref null func)
                       (ref null extern) (ref null 5) (ref null $t0))))
  (type (struct))
  (type (struct (field)))
  (type (struct (field i8)))
  (type (struct (field i8 i8 i8 i8)))
  (type (struct (field $x3 i32) (field $y3 i32)))
  (type (struct (field i8 i16 i32 i64 f32 f64 anyref funcref (ref 0) (ref null 1))))
  (type (struct (field i32 i64 i8) (field) (field) (field (ref null i31) anyref)))
  (type (struct (field $x4 i32) (field f32 f64) (field $y4 i32)))

  (type (array i8))
  (type (array i16))
  (type (array i32))
  (type (array i64))
  (type (array f32))
  (type (array f64))
  (type (array anyref))
  (type (array (ref struct)))
  (type (array (ref array)))
  (type (array (ref null struct)))
  (type (array (ref null array)))
  (type (array (ref 0)))
  (type (array (ref null 1)))
  (type (array (mut i8)))
  (type (array (mut i16)))
  (type (array (mut i32)))
  (type (array (mut i64)))
  (type (array (mut i32)))
  (type (array (mut i64)))
  (type (array (mut anyref)))
  (type (array (mut (ref struct))))
  (type (array (mut (ref array))))
  (type (array (mut (ref null struct))))
  (type (array (mut (ref null array))))
  (type (array (mut (ref 0))))
  (type (array (mut (ref null i31))))

  ;; sub types
  (type $e0 (sub (array i32)))
  (type $e1 (sub $e0 (array i32)))

  (type $e2 (sub (array anyref)))
  (type $e3 (sub (array (ref null $e0))))
  (type $e4 (sub (array (ref $e1))))
  (type $e5 (sub $e1 (array i32)))

  (type $m1 (sub (array (mut i32))))
  (type $m2 (sub $m1 (array (mut i32))))
)
