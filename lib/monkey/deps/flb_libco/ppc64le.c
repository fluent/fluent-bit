/*
  libco.ppc64le (2021-06-03)
*/

#define LIBCO_C
#include "libco.h"
#include "settings.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* state format (offsets in 32-bit words)

+0  SP
+8  CR save word
+12 Reserved
+16 LR save Doubleword
+24 TOC pointer doubleword
+32 Parameter save area
    GPRs
    FPRs
    VRs
    stack
*/

enum { state_size  = 1024 };
enum { above_stack = 2048 };
enum { stack_align = 256  };

static thread_local uint64_t co_active_buffer[1024];
static thread_local cothread_t co_active_handle = 0;

text_section
static const uint32_t libco_ppc_code[1024] = {
  0xf8240008, /* std r1, 8(4)     */
  0xf8440010, /* std r2, 16(4)    */
  0xf9840060, /* std r12, 96(4)   */
  0xf9a40068, /* std r13, 104(4)  */
  0xf9c40070, /* std r14, 112(4)  */
  0xf9e40078, /* std r15, 120(4)  */
  0xfa040080, /* std r16, 128(4)  */
  0xfa240088, /* std r17, 136(4)  */
  0xfa440090, /* std r18, 144(4)  */
  0xfa640098, /* std r19, 152(4)  */
  0xfa8400a0, /* std r20, 160(4)  */
  0xfaa400a8, /* std r21, 168(4)  */
  0xfac400b0, /* std r22, 176(4)  */
  0xfae400b8, /* std r23, 184(4)  */
  0xfb0400c0, /* std r24, 192(4)  */
  0xfb2400c8, /* std r25, 200(4)  */
  0xfb4400d0, /* std r26, 208(4)  */
  0xfb6400d8, /* std r27, 216(4)  */
  0xfb8400e0, /* std r28, 224(4)  */
  0xfba400e8, /* std r29, 232(4)  */
  0xfbc400f0, /* std r30, 240(4)  */
  0xfbe400f8, /* std r31, 248(4)  */
  0x7ca802a6, /* mflr r5          */
  0xf8a40100, /* std r5, 256(4)   */
  0x7ca00026, /* mfcr r5          */
  0xf8a40108, /* std r5, 264(4)   */
  0xe8230008, /* ld r1, 8(3)     */
  0xe8430010, /* ld r2, 16(3)    */
  0xe9830060, /* ld r12, 96(3)   */
  0xe9a30068, /* ld r13, 104(3)  */
  0xe9c30070, /* ld r14, 112(3)  */
  0xe9e30078, /* ld r15, 120(3)  */
  0xea030080, /* ld r16, 128(3)  */
  0xea230088, /* ld r17, 136(3)  */
  0xea430090, /* ld r18, 144(3)  */
  0xea630098, /* ld r19, 152(3)  */
  0xea8300a0, /* ld r20, 160(3)  */
  0xeaa300a8, /* ld r21, 168(3)  */
  0xeac300b0, /* ld r22, 176(3)  */
  0xeae300b8, /* ld r23, 184(3)  */
  0xeb0300c0, /* ld r24, 192(3)  */
  0xeb2300c8, /* ld r25, 200(3)  */
  0xeb4300d0, /* ld r26, 208(3)  */
  0xeb6300d8, /* ld r27, 216(3)  */
  0xeb8300e0, /* ld r28, 224(3)  */
  0xeba300e8, /* ld r29, 232(3)  */
  0xebc300f0, /* ld r30, 240(3)  */
  0xebe300f8, /* ld r31, 248(3)  */
  0xe8a30100, /* ld r5, 256(3)   */
  0x7ca803a6, /* mtlr r5         */
  0xe8a30108, /* ld r5, 264(3)   */
  0x7caff120, /* mtcr r5         */
  
  #ifndef LIBCO_PPC_NOFP
  0xd9c40180, /* stfd r14, 384(4) */
  0xd9e40188, /* stfd r15, 392(4) */
  0xda040190, /* stfd r16, 400(4) */
  0xda240198, /* stfd r17, 408(4) */
  0xda4401a0, /* stfd r18, 416(4) */
  0xda6401a8, /* stfd r19, 424(4) */
  0xda8401b0, /* stfd r20, 432(4) */
  0xdaa401b8, /* stfd r21, 440(4) */
  0xdac401c0, /* stfd r22, 448(4) */
  0xdae401c8, /* stfd r23, 456(4) */
  0xdb0401d0, /* stfd r24, 464(4) */
  0xdb2401d8, /* stfd r25, 472(4) */
  0xdb4401e0, /* stfd r26, 480(4) */
  0xdb6401e8, /* stfd r27, 488(4) */
  0xdb8401f0, /* stfd r28, 496(4) */
  0xdba401f8, /* stfd r29, 504(4) */
  0xdbc40200, /* stfd r30, 512(4) */
  0xdbe40208, /* stfd r31, 520(4) */
  0xc9c30180, /* lfd r14, 384(3) */
  0xc9e30188, /* lfd r15, 392(3) */
  0xca030190, /* lfd r16, 400(3) */
  0xca230198, /* lfd r17, 408(3) */
  0xca4301a0, /* lfd r18, 416(3) */
  0xca6301a8, /* lfd r19, 424(3) */
  0xca8301b0, /* lfd r20, 432(3) */
  0xcaa301b8, /* lfd r21, 440(3) */
  0xcac301c0, /* lfd r22, 448(3) */
  0xcae301c8, /* lfd r23, 456(3) */
  0xcb0301d0, /* lfd r24, 464(3) */
  0xcb2301d8, /* lfd r25, 472(3) */
  0xcb4301e0, /* lfd r26, 480(3) */
  0xcb6301e8, /* lfd r27, 488(3) */
  0xcb8301f0, /* lfd r28, 496(3) */
  0xcba301f8, /* lfd r29, 504(3) */
  0xcbc30200, /* lfd r30, 512(3) */
  0xcbe30208, /* lfd r31, 520(3) */
  #endif

  #ifdef __ALTIVEC__
  0x38a00210, /* li r5, 528        */
  0x7e842bce, /* stvxl v20, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7ea42bce, /* stvxl v21, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7ec42bce, /* stvxl v22, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7ee42bce, /* stvxl v23, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7f042bce, /* stvxl v24, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7f242bce, /* stvxl v25, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7f442bce, /* stvxl v26, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7f642bce, /* stvxl v27, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7f842bce, /* stvxl v28, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7fa42bce, /* stvxl v29, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7fc42bce, /* stvxl v30, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7fe42bce, /* stvxl v31, r4, r5 */
  0x38a50010, /* addi r5, r5, 16   */
  0x7ca042a6, /* mfvrsave r5       */
  0x90a402e0, /* stw r5, 736(4)    */
  0x38a00210, /* li r5, 528      */
  0x7e832ace, /* lvxl v20, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7ea32ace, /* lvxl v21, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7ec32ace, /* lvxl v22, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7ee32ace, /* lvxl v23, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7f032ace, /* lvxl v24, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7f232ace, /* lvxl v25, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7f432ace, /* lvxl v26, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7f632ace, /* lvxl v27, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7f832ace, /* lvxl v28, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7fa32ace, /* lvxl v29, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7fc32ace, /* lvxl v30, r3, r5 */
  0x38a50010, /* addi r5, r5, 16 */
  0x7fe32ace, /* lvxl v31, r3, 5  */
  0x38a50010, /* addi r5, r5, 16 */
  0x80a302d0, /* lwz r5, 720(3)  */
  0x7ca043a6, /* mtvrsave r5     */
  #endif

  0x4e800020  /* blr             */
};

/* function call goes directly to code */
#define CO_SWAP_ASM(x, y) ((void (*)(cothread_t, cothread_t))(uintptr_t)libco_ppc_code)(x, y)

static uint64_t* co_create_(unsigned size, uintptr_t entry) {
  (void)entry;
  uint64_t* t = (uint64_t*)malloc(size);
  return t;
}

cothread_t co_create(unsigned int size, void (*entry_)(void),
                     size_t *out_size) {

  uintptr_t entry = (uintptr_t)entry_;
  uint64_t* t = 0;

  /* be sure main thread was successfully allocated */
  if(co_active()) {
    t = co_create_(size, entry);
  }

  if(t) {
    uint8_t* sp;

    /* save current registers into new thread, so that any special ones will have proper values when thread is begun */
    CO_SWAP_ASM(t, t);

    /* put stack near end of block, and align */
    sp = (uint8_t*)t + size - above_stack;
    sp = (uint8_t*)((void*)((uintptr_t)(sp) & ~((stack_align) - 1)));

    /* set 0 to initial backchain */
    *(uint64_t*)sp = 0;

    /* new frame with backchain */
    sp -= above_stack;
    *(uint64_t*)sp = (uint64_t)(sp + above_stack);

    /* set up sp and entry will be called on next swap */
    t[1] = (uint64_t)sp;
    t[12] = (uint64_t)entry;
    t[32] = (uint64_t)entry;
  }
  *out_size = size;
  return t;
}

void co_delete(cothread_t t) {
  free(t);
}

cothread_t co_active() {
  if(!co_active_handle) co_active_handle = &co_active_buffer;

  return co_active_handle;
}

void co_switch(cothread_t t) {
  cothread_t old = co_active_handle;
  co_active_handle = t;

  CO_SWAP_ASM(t, old);
}
