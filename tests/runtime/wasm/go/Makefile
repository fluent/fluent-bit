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
