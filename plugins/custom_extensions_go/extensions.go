//  Fluent Bit Go!
//  ==============
//  Copyright (C) 2024 The Fluent Bit Go Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

package main

// #include <stdlib.h>
// #include "fluent-bit/flb_plugin.h"
// #include "fluent-bit/flb_plugin_proxy.h"
// #include "fluent-bit/flb_custom.h"
import "C"

import (
	"fmt"
	"time"
	"unsafe"
)

// Define constants matching Fluent Bit core
const (
	FLB_ERROR = C.FLB_ERROR
	FLB_OK    = C.FLB_OK
	FLB_RETRY = C.FLB_RETRY

	FLB_PROXY_CUSTOM_PLUGIN = C.FLB_CF_CUSTOM
	FLB_PROXY_GOLANG        = C.FLB_PROXY_GOLANG
)

// Local type to define a plugin definition
type (
	FLBPluginProxyDef C.struct_flb_plugin_proxy_def
	FLBCustomInstance C.struct_flb_custom_instance
)

// When the FLBPluginInit is triggered by Fluent Bit, a plugin context
// is passed and the next step is to invoke this FLBPluginRegister() function
// to fill the required information: type, proxy type, flags name and
// description.
//
//export FLBPluginRegister
func FLBPluginRegister(def unsafe.Pointer, name, desc string) int {
	p := (*FLBPluginProxyDef)(def)
	p._type = FLB_PROXY_CUSTOM_PLUGIN
	p.proxy = FLB_PROXY_GOLANG
	p.flags = 0
	p.name = C.CString(name)
	p.description = C.CString(desc)
	return 0
}

// (fluentbit will call this)
// plugin (context) pointer to fluentbit context (state/ c code)
//
//export FLBPluginInit
func FLBPluginInit(plugin unsafe.Pointer) int {
	extensions := FLBPluginConfigKey(plugin, "extensions")
	fmt.Printf("[flb-go] extensions = '%s'\n", extensions)
	go func() {
		for {
			fmt.Printf("[flb-go] Go extensions alive %v\n", time.Now())
			time.Sleep(10 * time.Second)
		}
	}()
	return FLB_OK
}

// Release resources allocated by the plugin initialization
//
//export FLBPluginUnregister
func FLBPluginUnregister(def unsafe.Pointer) {
	p := (*FLBPluginProxyDef)(def)
	C.free(unsafe.Pointer(p.name))
	C.free(unsafe.Pointer(p.description))
}

//export FLBPluginExit
func FLBPluginExit() int {
	return FLB_OK
}

func FLBPluginConfigKey(plugin unsafe.Pointer, key string) string {
	k := C.CString(key)
	p := plugin
	v := C.GoString(C.flb_custom_get_property(k, (*C.struct_flb_custom_instance)(p)))
	C.free(unsafe.Pointer(k))
	return v
}

func main() {
}
