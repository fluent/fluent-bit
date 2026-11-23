.PHONY: build

build: append_tag numeric_records say_hello modify_record

append_tag:
	tinygo build -wasm-abi=generic -target=wasi -o $@.wasm $@.go

modify_record:
	tinygo build -wasm-abi=generic -target=wasi -o $@.wasm $@.go

numeric_records:
	tinygo build -wasm-abi=generic -target=wasi -o $@.wasm $@.go

say_hello:
	tinygo build -wasm-abi=generic -target=wasi -o $@.wasm $@.go

drop_record:
	tinygo build -wasm-abi=generic -target=wasi -o $@.wasm $@.go

testdata:
	cp *.wasm ../../data/wasm

clean:
	rm -f *.wasm

# ABI v2 fixture is built from the runnable TinyGo example.
# TinyGo 0.35 requires Go 1.19-1.23; use a compatible GOROOT/PATH.
v2:
	tinygo build -target=wasi -scheduler=none -o ../../data/wasm/filter_go_v2.wasm ../../../../examples/filter_wasm_go/v2/filter.go
