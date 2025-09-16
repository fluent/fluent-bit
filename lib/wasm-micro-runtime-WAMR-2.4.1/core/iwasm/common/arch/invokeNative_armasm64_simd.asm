        ; Copyright (C) 2019 Intel Corporation.  All rights reserved.
        ; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

        AREA    |.text|, CODE, READONLY, ALIGN=2

        EXPORT  invokeNative

; ------------------------ direct call path ------------------------

call_func
        mov     x20, x30                 ; save x30(lr)
        blr     x19
        mov     sp, x22                  ; restore sp saved before function call

return_label
        mov     x30,  x20                ; restore x30(lr)
        ldp     x19, x20, [sp, #0x20]
        ldp     x21, x22, [sp, #0x10]
        ldp     x23, x24, [sp, #0x0]
        add     sp, sp, #0x30
        ret

; ------------------------ stack-args path ------------------------

handle_stack
        ; Reserve aligned stack space for stack arguments and copy them
        mov     x23, sp
        bic     sp,  x23, #15            ; Ensure 16-byte alignment
        lsl     x23, x21, #3             ; x23 = nstacks * 8
        add     x23, x23, #15
        bic     x23, x23, #15
        sub     sp, sp, x23
        mov     x23, sp

copy_loop
        cmp     x21, #0
        b.eq    call_func                ; when done, branch back to call path
        ldr     x24, [x20], #8
        str     x24, [x23], #8
        sub     x21, x21, #1
        b       copy_loop

; ------------------------ function entry ------------------------

invokeNative
        sub     sp, sp, #0x30
        stp     x19, x20, [sp, #0x20]    ; save the registers
        stp     x21, x22, [sp, #0x10]
        stp     x23, x24, [sp, #0x0]

        mov     x19, x0                  ; x19 = function ptr
        mov     x20, x1                  ; x20 = argv
        mov     x21, x2                  ; x21 = nstacks
        mov     x22, sp                  ; save the sp before call function

        ; Fill in floating-point registers
        ; v0 = argv[0], v1 = argv[1], v2 = argv[2], v3 = argv[3]
        ld1     {v0.2D, v1.2D, v2.2D, v3.2D}, [x20], #64
        ; v4 = argv[4], v5 = argv[5], v6 = argv[6], v7 = argv[7]
        ld1     {v4.2D, v5.2D, v6.2D, v7.2D}, [x20], #64

        ; Fill integer registers
        ldp     x0, x1, [x20], #16       ; x0 = argv[8] = exec_env, x1 = argv[9]
        ldp     x2, x3, [x20], #16
        ldp     x4, x5, [x20], #16
        ldp     x6, x7, [x20], #16

        ; Now x20 points to stack args
        cmp     x21, #0
        b.ne    handle_stack             ; (backward) there are stack args
        b       call_func                ; (backward) no stack args

        END
