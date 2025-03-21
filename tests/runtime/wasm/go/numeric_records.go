package main

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/valyala/fastjson"
)

//export filter_numeric_records
func filter_numeric_records(tag *uint8, tag_len uint, time_sec uint, time_nsec uint, record *uint8, record_len uint) *uint8 {
	_ = unsafe.Slice(tag, tag_len)  // Note, requires Go 1.17+ (tinygo 0.20+)
	brecord := unsafe.Slice(record, record_len)
	_ = time.Unix(int64(time_sec), int64(time_nsec))

	br := string(brecord)
	var p fastjson.Parser
	value, err := p.Parse(br)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	obj, err := value.Object()
	if err != nil {
		fmt.Println(err)
		return nil
	}

	var arena fastjson.Arena
	obj.Set("wasm_int1", arena.NewNumberInt(10))
	obj.Set("wasm_int2", arena.NewNumberInt(100))
	obj.Set("wasm_float1", arena.NewNumberFloat64(10.5))
	obj.Set("wasm_float2", arena.NewNumberFloat64(100.5))
	obj.Set("wasm_truncate_float", arena.NewNumberFloat64(120.0))
	obj.Set("wasm_exp_float", arena.NewNumberFloat64(3.54789e-3))
	s := obj.String()
	s += string(rune(0)) // Note: explicit null terminator.
	rv := []byte(s)

	return &rv[0]
}

func main() {}
