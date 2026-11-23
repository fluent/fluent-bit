package main

import "unsafe"

// valueLength packs a wasm32 memory offset and its byte length into one i64.
func valueLength(value *byte, length uint32) uint64 {
	return uint64(length)<<32 | uint64(uint32(uintptr(unsafe.Pointer(value))))
}

// filter_v2 returns the original body as a value-length pair. The input is
// borrowed: Fluent Bit copies the result before releasing the buffer.
//
//export filter_v2
func filter_v2(tag *byte, tagLength uint32, seconds uint32, nanoseconds uint32,
	record *byte, recordLength uint32) uint64 {
	return valueLength(record, recordLength)
}

// Module-owned storage remains valid after the exported function returns.
// This MessagePack map is {"n": 0, "s": "a\x00b"}.
var binaryBody = [...]byte{0x82, 0xa1, 'n', 0, 0xa1, 's', 0xa3, 'a', 0, 'b'}

//export filter_binary_v2
func filter_binary_v2(tag *byte, tagLength uint32, seconds uint32, nanoseconds uint32,
	record *byte, recordLength uint32) uint64 {
	return valueLength(&binaryBody[0], uint32(len(binaryBody)))
}

//export filter_drop_v2
func filter_drop_v2(tag *byte, tagLength uint32, seconds uint32, nanoseconds uint32,
	record *byte, recordLength uint32) uint64 {
	return 0
}

func main() {}
