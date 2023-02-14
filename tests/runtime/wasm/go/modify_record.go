package main

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/valyala/fastjson"
)

//export filter_modify_record
func filter_modify_record(tag *uint8, tag_len uint, time_sec uint, time_nsec uint, record *uint8, record_len uint) *uint8 {
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
	obj.Set("modify", arena.NewString(string("yes")))
	s := obj.String()
	s += string(rune(0)) // Note: explicit null terminator.
	rv := []byte(s)

	return &rv[0]
}

func main() {}
