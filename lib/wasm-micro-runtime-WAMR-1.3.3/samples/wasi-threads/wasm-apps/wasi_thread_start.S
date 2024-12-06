# A slightly modified copy of the wasi-libc implementation
# https://github.com/WebAssembly/wasi-libc/pull/376/
	.globaltype	__stack_pointer, i32
	.functype	__wasi_thread_start_C (i32, i32) -> ()

	.globl	wasi_thread_start

wasi_thread_start:
	.functype	wasi_thread_start (i32, i32) -> ()

	# Set up the minimum C environment.
	# Note: offsetof(start_arg, stack) == 0
	local.get   1  # start_arg
	i32.load    0  # stack
	global.set  __stack_pointer

	# Make the C function do the rest of work.
	local.get   0  # tid
	local.get   1  # start_arg
	call __wasi_thread_start_C

	end_function