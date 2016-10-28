package main

/*
#define FLB_PROXY_OUTPUT_PLUGIN    2
#define FLB_PROXY_GOLANG          11

struct flb_plugin_proxy {
    int type;
    int proxy;
    int flags;
    char *name;
    char *description;
};
*/
import "C"
import "unsafe"
import "fmt"
import "github.com/ugorji/go/codec"

type FLBOutPlugin C.struct_flb_plugin_proxy

//export flb_cb_init
func flb_cb_init() int {
	fmt.Printf("[GO] cb_init() ===> init callback\n")
	return 0
}

//export flb_cb_register
func flb_cb_register() *FLBOutPlugin {
	p := (*FLBOutPlugin)(C.malloc(C.size_t(unsafe.Sizeof(FLBOutPlugin{}))))
	p._type       = C.FLB_PROXY_OUTPUT_PLUGIN
	p.proxy       = C.FLB_PROXY_GOLANG
	p.flags       = 0
	p.name        = C.CString("gstdout")
	p.description = C.CString("Go STDOUT plugin")
	return p
}

//export flb_cb_flush
func flb_cb_flush(data unsafe.Pointer, length C.int, tag *C.char) int {
	var count int
	var h codec.Handle = new(codec.MsgpackHandle)
	var b []byte
	var m interface{}
	var err error

	b = C.GoBytes(data, length)
	dec := codec.NewDecoderBytes(b, h)

	count = 0
	for {
		err = dec.Decode(&m)
		if err != nil {
			break
		}
		fmt.Printf("[%d] %s: %v\n", count, C.GoString(tag), m)
		count++
	}

	return 0
}

//export flb_cb_exit
func flb_cb_exit() int {
	return 0
}

func main() {
}
