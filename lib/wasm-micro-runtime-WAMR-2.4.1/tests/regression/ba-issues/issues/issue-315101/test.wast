(module
 (data $string_data "asdf")
 (func $print (import "spectest" "print_i32") (param $i i32))
 (memory $memory (export "memory") 1)
 (type $string (array (mut i8)))
 (type $var (struct (field (ref null $string))))

 (func $test (param $param (ref $var))
    (local.get $param)
    (struct.get $var 0) 
    (ref.as_non_null)
    (array.len)
    (call $print)
 )
 (func $init
    (local $str (ref $string))
    (array.new_data $string $string_data (i32.const 0) (i32.const 4))
    (local.set $str)
    (struct.new $var (local.get $str))
    (call $test)
 )

 (export "_start" (func $init))
)
