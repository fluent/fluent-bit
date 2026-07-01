package main

import (
	"C"
	"fmt"
	"unsafe"

	"github.com/fluent/fluent-bit-go/output"
)

//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer) int {
	// Register as logs-only output plugin
	return output.FLBPluginRegister(def, "test_logs_go", "Test Go Output Plugin for Logs")
}

//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	return output.FLB_OK
}

//export FLBPluginFlushCtx
func FLBPluginFlushCtx(ctx, data unsafe.Pointer, length C.int, tag *C.char) int {
	// Write to a stdout to verify it received data
	dec := output.NewDecoder(data, int(length))
	var logrecords []string
	for {
		ret, _, record := output.GetRecord(dec)
		if ret != 0 {
			break
		}
		logrecords = append(logrecords, fmt.Sprintf("%v", record))
	}
	for _, record := range logrecords {
		fmt.Printf("%s\n", record)
	}

	return output.FLB_OK
}

//export FLBPluginExit
func FLBPluginExit() int {
	return output.FLB_OK
}

func main() {
}
