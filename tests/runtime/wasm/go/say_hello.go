package main

import (
	"fmt"
)

//export filter_say_hello
func filter_say_hello(tag *uint8, tag_len uint, time_sec uint, time_nsec uint, record *uint8, record_len uint) *uint8 {
	fmt.Println("Hello from WASM!")

	return record
}

func main() {}
