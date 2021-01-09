

call golib from c

example go src:

```go

package main

import "C"
import (
	"fmt"
)

const FLB_OK = 0

//export FLBPluginInit
func FLBPluginInit(name, value []string) int {

	fmt.Printf("get name %#v. ", name)
	fmt.Printf("get value %#v. ", value)

	return FLB_OK
}

//export FLBPluginFilter
func FLBPluginFilter(srcName, srcValue []string) int {
	// go will return the result in the slice which called in. so can't append item that max slice's cap.
	// must use cgoAppend instead of append if you want append value.
	// use cgoSetSlice if you want change value of slice or just append.

	src := loadCallIn(srcName, srcValue)

	src["myadd"] ="teat"

	return unLoadCallIn(src, srcName, srcValue)
}

//export FLBPluginExit
func FLBPluginExit() int {

	fmt.Println("go exit")

	return FLB_OK
}

func loadCallIn(name, value[]string) map[string]string  {
	res := make(map[string]string)
	for idx, n := range name {
		res[n] = value[idx]
	}
	return res
}

func unLoadCallIn(src map[string]string, name, value []string) int  {
	index := 0
	for k, v := range src {
		name = cgoSetSlice(name, index, k)
		value = cgoSetSlice(value, index, v)
		index++
	}
	fmt.Println("unload ok: ", name, value)
	return index;
}


// can't append parameters that will over slice's cap.
// if over slice's cap, then go will malloc new memory, the c can't get the results.
func cgoAppend(src []string, parameters... string) []string {
	if cap(src) - len(src) < len(parameters) {
		fmt.Println(" cann't set parameters. slice cap is full. ", len(src) , cap(src), len(parameters))
		return src
	}
	src = append(src, parameters...)
	return src
}

func cgoSetSlice(src []string, index int, value string) []string {
	if index > cap(src) {
		fmt.Println(" cann't set parameters. index overflow. ", index, cap(src))
		return src
	}

	if index >= len(src) {
		src = append(src, value)
	} else {
		src[index] = value
	}

	return src
}

func main()  {}

```

build

```shell
go build -o cgolib.so -buildmode=c-shared cgolib.go
```

config

```ini
[FILTER]
    Name     go
    Match    *
    golib_so /usr/local/libs/cgolib.so
    url      http://example1.com
    url2     http://example2.com
```
