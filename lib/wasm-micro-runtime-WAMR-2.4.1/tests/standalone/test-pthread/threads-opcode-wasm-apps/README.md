# "Unit Test" Testsuite for Threads Opcode

These tests are meant to **test the atomicity** of threads code. Initially, they were meant to test if the fast JIT implementation is correct, but they can also be used to test other running modes. The semantics correctness (operating with the correct number of bytes in memory and returning the correct value) have already been tested in spec tests (single-thread environment).

## Test Cases Opcode Coverage

> **Atomicity** of **all** threads opcodes are **fully tested** with these cases.
>
> **&#9745; Only indicates** there is a WASM test case to **test the atomicity directly.** The atomicity of other opcodes **without &#9745;** is **tested indirectly.** Indirect testing means that it is either implicit with other cases in this directory or tested pragmatically correct (atomicity and semantic correctness together) in pthread or WASI-threads test cases.

Click the link to see the details of how each opcode is tested.

- RMW (Read-Modify-Write):
  - [CMPXCHG opcode](#cmpxchg) &#9745;
  - Arithmetic:
    - [ADD opcode](#arithmetic-add-sub-and-xchg) &#9745;
    - [SUB opcode](#arithmetic-add-sub-and-xchg) &#9745;
    - [XCHG opcode](#arithmetic-add-sub-and-xchg) &#9745;
  - Logical:
    - [AND opcode](#logical-or-xor-and)
    - [OR opcode](#logical-or-xor-and)
    - [XOR opcode](#logical-or-xor-and) &#9745;

- [LOAD](#atomic-ldstfence)

- [STORE](#atomic-ldstfence) &#9745;

- [FENCE](#atomic-ldstfence) &#9745;

- [WAIT & NOTIFY](#atomic-waitnotify) &#9745;

## Details

### atomic rmw

#### arithmetic (`add`, `sub`) and xchg

- `add, sub`: in [atomic_add_sub.c](./atomic_add_sub.c), **__atomic_fetch_add/sub()** to generate wasm opcode atomic.add/sub

- `xchg`: in x86-64 implementation, wasm code atomic `store` and `xchg` generate same asm instruction xchg, should be enough to only test with store(tested in [atomic_store.c](./atomic_store.c)). But add a `atomic_xchg.c` to use **__atomic_exchange()** to generate wasm opcode xchg and test it anyways(tested in [atomic_xchg.c](./atomic_xchg.c)).

#### logical `or`, `xor`, `and`

- logical `or`, `xor`, `and`: those three opcodes are similar, it all generate a loop, inside which uses corresponding asm instruction do logical operation and locked cmpxchg to atomically modify the memory. So in a sense, test it will implicitly test the atomicity of cmpxchg.

  in [atomic_logical.c](./atomic_logical.c), tested `xor` wasm opcode to test the atomicity of the generated loop:

  - make use of operation "n `xor` n -> 0", when n range from 1 to 9999, 4 thread concurrently xor the same variable, the final result should be 0.
  
  The generated loop of `xor` is atomic -> generated loop of `or`, `and` is also atomic

#### cmpxchg

- wasm opcode `cmpxchg` already tested together with other opcodes in multiple wasi-thread cases. Logical opcodes generate asm instruction lock cmpxchg, the atomicity of generated asm code is proven in logical opcode. In [atomic_wait&&notify.c](./atomic_wait_notify.c), it also tests the opcode `cmpxchg`

### atomic ld/st/fence

use peterson lock algorithm, in [atomic_fence.c](./atomic_fence.c) to test the atomicity of `fence`

> PS: since the interpreter is relatively slow compared to JIT/AOT mode, it's less likely(almost impossible) to trigger processor-level behavior: instructions to be ordered within a single thread

The prerequisite for peterson lock properly is that load and store have to be `Sequential Consistency`, which can be achieved use:

1. LOAD (without fence) and STORE + MFENCE -> use it to test `fence` opcode
2. LOAD (without fence) and LOCK XCHG -> use it to test atomic `store` opcode
3. MFENCE + LOAD and STORE (without fence)
4. LOCK XADD ( 0 ) and STORE (without fence)

### atomic wait&notify

Actually in every pthread tests, it will generate `wait` and `notify`, it is also tested in in multiple wasi-thread cases.

But add a [atomic_wait&&notify.c](./atomic_wait_notify.c) to test it anyways.
