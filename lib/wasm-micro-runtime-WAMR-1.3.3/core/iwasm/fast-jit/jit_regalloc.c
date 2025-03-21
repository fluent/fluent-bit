/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_utils.h"
#include "jit_compiler.h"

#if BH_DEBUG != 0
#define VREG_DEF_SANITIZER
#endif

/**
 * A uint16 stack for storing distances of occurrences of virtual
 * registers.
 */
typedef struct UintStack {
    /* Capacity of the stack.  */
    uint32 capacity;

    /* Top index of the stack.  */
    uint32 top;

    /* Elements of the vector.  */
    uint32 elem[1];
} UintStack;

static bool
uint_stack_push(UintStack **stack, unsigned val)
{
    unsigned capacity = *stack ? (*stack)->capacity : 0;
    unsigned top = *stack ? (*stack)->top : 0;

    bh_assert(top <= capacity);

    if (top == capacity) {
        const unsigned elem_size = sizeof((*stack)->elem[0]);
        unsigned new_capacity = capacity ? capacity + capacity / 2 : 4;
        UintStack *new_stack =
            jit_malloc(offsetof(UintStack, elem) + elem_size * new_capacity);

        if (!new_stack)
            return false;

        new_stack->capacity = new_capacity;
        new_stack->top = top;

        if (*stack)
            memcpy(new_stack->elem, (*stack)->elem, elem_size * top);

        jit_free(*stack);
        *stack = new_stack;
    }

    (*stack)->elem[(*stack)->top++] = val;

    return true;
}

static int
uint_stack_top(UintStack *stack)
{
    return stack->elem[stack->top - 1];
}

static void
uint_stack_delete(UintStack **stack)
{
    jit_free(*stack);
    *stack = NULL;
}

static void
uint_stack_pop(UintStack **stack)
{
    bh_assert((*stack)->top > 0);

    /**
     * TODO: the fact of empty distances stack means there is no instruction
     * using current JitReg anymore. so shall we release the HardReg and clean
     * VirtualReg information?
     */
    if (--(*stack)->top == 0)
        uint_stack_delete(stack);
}

/**
 * Information of a virtual register.
 */
typedef struct VirtualReg {
    /* The hard register allocated to this virtual register.  */
    JitReg hreg;

    /* The spill slot allocated to this virtual register.  */
    JitReg slot;

    /* The hard register allocated to global virtual registers.  It is 0
       for local registers, whose lifetime is within one basic block.  */
    JitReg global_hreg;

    /* Distances from the beginning of basic block of all occurrences of the
       virtual register in the basic block.  */
    UintStack *distances;
} VirtualReg;

/**
 * Information of a hard register.
 */
typedef struct HardReg {
    /* The virtual register this hard register is allocated to.  */
    JitReg vreg;
} HardReg;

/**
 * Information of a spill slot.
 */
typedef struct SpillSlot {
    /* The virtual register this spill slot is allocated to.  */
    JitReg vreg;
} SpillSlot;

typedef struct RegallocContext {
    /* The compiler context.  */
    JitCompContext *cc;

    /* Information of virtual registers.  The register allocation must
       not increase the virtual register number during the allocation
       process.  */
    VirtualReg *vregs[JIT_REG_KIND_L32];

    /* Information of hard registers. */
    HardReg *hregs[JIT_REG_KIND_L32];

    /* Number of elements in the spill_slots array.  */
    uint32 spill_slot_num;

    /* Information of spill slots.  */
    SpillSlot *spill_slots;

    /* The last define-released hard register.  */
    JitReg last_def_released_hreg;
} RegallocContext;

/**
 * Get the VirtualReg structure of the given virtual register.
 *
 * @param rc the regalloc context
 * @param vreg the virtual register
 *
 * @return the VirtualReg structure of the given virtual register
 */
static VirtualReg *
rc_get_vr(RegallocContext *rc, JitReg vreg)
{
    unsigned kind = jit_reg_kind(vreg);
    unsigned no = jit_reg_no(vreg);

    bh_assert(jit_reg_is_variable(vreg));
    bh_assert(kind < JIT_REG_KIND_L32);

    return &rc->vregs[kind][no];
}

/**
 * Get the HardReg structure of the given hard register.
 *
 * @param rc the regalloc context
 * @param hreg the hard register
 *
 * @return the HardReg structure of the given hard register
 */
static HardReg *
rc_get_hr(RegallocContext *rc, JitReg hreg)
{
    unsigned kind = jit_reg_kind(hreg);
    unsigned no = jit_reg_no(hreg);

    bh_assert(jit_reg_is_variable(hreg) && jit_cc_is_hreg(rc->cc, hreg));
    bh_assert(kind < JIT_REG_KIND_L32);

    return &rc->hregs[kind][no];
}

/**
 * Get the SpillSlot structure of the given slot.
 *
 * @param rc the regalloc context
 * @param slot the constant register representing the slot index
 *
 * @return the SpillSlot of the given slot
 */
static SpillSlot *
rc_get_spill_slot(RegallocContext *rc, JitReg slot)
{
    unsigned index = jit_cc_get_const_I32(rc->cc, slot);

    bh_assert(index < rc->spill_slot_num);

    return &rc->spill_slots[index];
}

/**
 * Get the stride in the spill slots of the register.
 *
 * @param reg a virtual register
 *
 * @return stride in the spill slots
 */
static unsigned
get_reg_stride(JitReg reg)
{
    static const uint8 strides[] = { 0, 1, 2, 1, 2, 2, 4, 8, 0 };
    uint32 kind = jit_reg_kind(reg);
    bh_assert(kind <= JIT_REG_KIND_L32);
    return strides[kind];
}

/**
 * Allocate a spill slot for the given virtual register.
 *
 * @param rc the regalloc context
 * @param vreg the virtual register
 *
 * @return the spill slot encoded in a consant register
 */
static JitReg
rc_alloc_spill_slot(RegallocContext *rc, JitReg vreg)
{
    const unsigned stride = get_reg_stride(vreg);
    unsigned mask, new_num, i, j;
    SpillSlot *slots;

    bh_assert(stride > 0);

    for (i = 0; i < rc->spill_slot_num; i += stride)
        for (j = i;; j++) {
            if (j == i + stride)
                /* Found a free slot for vreg.  */
                goto found;

            if (rc->spill_slots[j].vreg)
                break;
        }

    /* No free slot, increase the slot number.  */
    mask = stride - 1;
    /* Align the slot index.  */
    i = (rc->spill_slot_num + mask) & ~mask;
    new_num = i == 0 ? 32 : i + i / 2;

    if (!(slots = jit_calloc(sizeof(*slots) * new_num)))
        return 0;

    if (rc->spill_slots)
        memcpy(slots, rc->spill_slots, sizeof(*slots) * rc->spill_slot_num);

    jit_free(rc->spill_slots);
    rc->spill_slots = slots;
    rc->spill_slot_num = new_num;

found:
    /* Now, i is the first slot for vreg.  */
    if ((i + stride) * 4 > rc->cc->spill_cache_size)
        /* No frame space for the spill area.  */
        return 0;

    /* Allocate the slot(s) to vreg.  */
    for (j = i; j < i + stride; j++)
        rc->spill_slots[j].vreg = vreg;

    return jit_cc_new_const_I32(rc->cc, i);
}

/**
 * Free a spill slot.
 *
 * @param rc the regalloc context
 * @param slot_reg the constant register representing the slot index
 */
static void
rc_free_spill_slot(RegallocContext *rc, JitReg slot_reg)
{
    if (slot_reg) {
        SpillSlot *slot = rc_get_spill_slot(rc, slot_reg);
        const JitReg vreg = slot->vreg;
        const unsigned stride = get_reg_stride(vreg);
        unsigned i;

        for (i = 0; i < stride; i++)
            slot[i].vreg = 0;
    }
}

static void
rc_destroy(RegallocContext *rc)
{
    unsigned i, j;

    for (i = JIT_REG_KIND_VOID; i < JIT_REG_KIND_L32; i++) {
        const unsigned vreg_num = jit_cc_reg_num(rc->cc, i);

        if (rc->vregs[i])
            for (j = 0; j < vreg_num; j++)
                uint_stack_delete(&rc->vregs[i][j].distances);

        jit_free(rc->vregs[i]);
        jit_free(rc->hregs[i]);
    }

    jit_free(rc->spill_slots);
}

static bool
rc_init(RegallocContext *rc, JitCompContext *cc)
{
    unsigned i, j;

    memset(rc, 0, sizeof(*rc));
    rc->cc = cc;

    for (i = JIT_REG_KIND_VOID; i < JIT_REG_KIND_L32; i++) {
        const unsigned vreg_num = jit_cc_reg_num(cc, i);
        const unsigned hreg_num = jit_cc_hreg_num(cc, i);

        if (vreg_num > 0
            && !(rc->vregs[i] = jit_calloc(sizeof(VirtualReg) * vreg_num)))
            goto fail;
        if (hreg_num > 0
            && !(rc->hregs[i] = jit_calloc(sizeof(HardReg) * hreg_num)))
            goto fail;

        /* Hard registers can only be allocated to themselves.  */
        for (j = 0; j < hreg_num; j++)
            rc->vregs[i][j].global_hreg = jit_reg_new(i, j);
    }

    return true;

fail:
    rc_destroy(rc);

    return false;
}

/**
 * Check whether the given register is an allocation candidate, which
 * must be a variable register that is not fixed hard register.
 *
 * @param cc the compilation context
 * @param reg the register
 *
 * @return true if the register is an allocation candidate
 */
static bool
is_alloc_candidate(JitCompContext *cc, JitReg reg)
{
    return (jit_reg_is_variable(reg)
            && (!jit_cc_is_hreg(cc, reg) || !jit_cc_is_hreg_fixed(cc, reg)));
}

#ifdef VREG_DEF_SANITIZER
static void
check_vreg_definition(RegallocContext *rc, JitInsn *insn)
{
    JitRegVec regvec = jit_insn_opnd_regs(insn);
    JitReg *regp, reg_defined = 0;
    unsigned i, first_use = jit_insn_opnd_first_use(insn);

    /* check if there is the definition of an vr before its references */
    JIT_REG_VEC_FOREACH(regvec, i, regp)
    {
        VirtualReg *vr = NULL;

        if (!is_alloc_candidate(rc->cc, *regp))
            continue;

        /* a strong assumption that there is only one defined reg */
        if (i < first_use) {
            reg_defined = *regp;
            continue;
        }

        /**
         * both definition and references are in one instruction,
         * like MOV i3, i3
         */
        if (reg_defined == *regp)
            continue;

        vr = rc_get_vr(rc, *regp);
        bh_assert(vr->distances);
    }
}
#endif

/**
 * Collect distances from the beginning of basic block of all occurrences of
 * each virtual register.
 *
 * @param rc the regalloc context
 * @param basic_block the basic block
 *
 * @return distance of the end instruction if succeeds, -1 otherwise
 */
static int
collect_distances(RegallocContext *rc, JitBasicBlock *basic_block)
{
    JitInsn *insn;
    int distance = 1;

    JIT_FOREACH_INSN(basic_block, insn)
    {
#if WASM_ENABLE_SHARED_MEMORY != 0
        /* fence insn doesn't have any operand, hence, no regs involved */
        if (insn->opcode == JIT_OP_FENCE) {
            continue;
        }
#endif

        JitRegVec regvec = jit_insn_opnd_regs(insn);
        unsigned i;
        JitReg *regp;

#ifdef VREG_DEF_SANITIZER
        check_vreg_definition(rc, insn);
#endif

        /* NOTE: the distance may be pushed more than once if the
           virtual register occurs multiple times in the
           instruction.  */
        JIT_REG_VEC_FOREACH(regvec, i, regp)
        if (is_alloc_candidate(rc->cc, *regp))
            if (!uint_stack_push(&(rc_get_vr(rc, *regp))->distances, distance))
                return -1;

        /* Integer overflow check, normally it won't happen, but
           we had better add the check here */
        if (distance >= INT32_MAX)
            return -1;

        distance++;
    }

    return distance;
}

static JitReg
offset_of_spill_slot(JitCompContext *cc, JitReg slot)
{
    return jit_cc_new_const_I32(cc, cc->spill_cache_offset
                                        + jit_cc_get_const_I32(cc, slot) * 4);
}

/**
 * Reload the virtual register from memory.  Reload instruction will
 * be inserted after the given instruction.
 *
 * @param rc the regalloc context
 * @param vreg the virtual register to be reloaded
 * @param cur_insn the current instruction after which the reload
 * insertion will be inserted
 *
 * @return the reload instruction if succeeds, NULL otherwise
 */
static JitInsn *
reload_vreg(RegallocContext *rc, JitReg vreg, JitInsn *cur_insn)
{
    VirtualReg *vr = rc_get_vr(rc, vreg);
    HardReg *hr = rc_get_hr(rc, vr->hreg);
    JitInsn *insn = NULL;

    if (vreg == rc->cc->exec_env_reg)
        /* Reload exec_env_reg with LDEXECENV.  */
        insn = jit_cc_new_insn(rc->cc, LDEXECENV, vr->hreg);
    else
    /* Allocate spill slot if not yet and reload from there.  */
    {
        JitReg fp_reg = rc->cc->fp_reg, offset;

        if (!vr->slot && !(vr->slot = rc_alloc_spill_slot(rc, vreg)))
            /* Cannot allocte spill slot (due to OOM or frame size limit).  */
            return NULL;

        offset = offset_of_spill_slot(rc->cc, vr->slot);

        switch (jit_reg_kind(vreg)) {
            case JIT_REG_KIND_I32:
                insn = jit_cc_new_insn(rc->cc, LDI32, vr->hreg, fp_reg, offset);
                break;
            case JIT_REG_KIND_I64:
                insn = jit_cc_new_insn(rc->cc, LDI64, vr->hreg, fp_reg, offset);
                break;
            case JIT_REG_KIND_F32:
                insn = jit_cc_new_insn(rc->cc, LDF32, vr->hreg, fp_reg, offset);
                break;
            case JIT_REG_KIND_F64:
                insn = jit_cc_new_insn(rc->cc, LDF64, vr->hreg, fp_reg, offset);
                break;
            case JIT_REG_KIND_V64:
                insn = jit_cc_new_insn(rc->cc, LDV64, vr->hreg, fp_reg, offset);
                break;
            case JIT_REG_KIND_V128:
                insn =
                    jit_cc_new_insn(rc->cc, LDV128, vr->hreg, fp_reg, offset);
                break;
            case JIT_REG_KIND_V256:
                insn =
                    jit_cc_new_insn(rc->cc, LDV256, vr->hreg, fp_reg, offset);
                break;
            default:
                bh_assert(0);
        }
    }

    if (insn)
        jit_insn_insert_after(cur_insn, insn);

    bh_assert(hr->vreg == vreg);
    hr->vreg = vr->hreg = 0;

    return insn;
}

/**
 * Spill the virtual register (which cannot be exec_env_reg) to memory.
 * Spill instruction will be inserted after the given instruction.
 *
 * @param rc the regalloc context
 * @param vreg the virtual register to be reloaded
 * @param cur_insn the current instruction after which the reload
 * insertion will be inserted
 *
 * @return the spill instruction if succeeds, NULL otherwise
 */
static JitInsn *
spill_vreg(RegallocContext *rc, JitReg vreg, JitInsn *cur_insn)
{
    VirtualReg *vr = rc_get_vr(rc, vreg);
    JitReg fp_reg = rc->cc->fp_reg, offset;
    JitInsn *insn;

    /* There is no chance to spill exec_env_reg.  */
    bh_assert(vreg != rc->cc->exec_env_reg);
    bh_assert(vr->hreg && vr->slot);
    offset = offset_of_spill_slot(rc->cc, vr->slot);

    switch (jit_reg_kind(vreg)) {
        case JIT_REG_KIND_I32:
            insn = jit_cc_new_insn(rc->cc, STI32, vr->hreg, fp_reg, offset);
            break;
        case JIT_REG_KIND_I64:
            insn = jit_cc_new_insn(rc->cc, STI64, vr->hreg, fp_reg, offset);
            break;
        case JIT_REG_KIND_F32:
            insn = jit_cc_new_insn(rc->cc, STF32, vr->hreg, fp_reg, offset);
            break;
        case JIT_REG_KIND_F64:
            insn = jit_cc_new_insn(rc->cc, STF64, vr->hreg, fp_reg, offset);
            break;
        case JIT_REG_KIND_V64:
            insn = jit_cc_new_insn(rc->cc, STV64, vr->hreg, fp_reg, offset);
            break;
        case JIT_REG_KIND_V128:
            insn = jit_cc_new_insn(rc->cc, STV128, vr->hreg, fp_reg, offset);
            break;
        case JIT_REG_KIND_V256:
            insn = jit_cc_new_insn(rc->cc, STV256, vr->hreg, fp_reg, offset);
            break;
        default:
            bh_assert(0);
            return NULL;
    }

    if (insn)
        jit_insn_insert_after(cur_insn, insn);

    return insn;
}

/**
 * Allocate a hard register for the virtual register.  Necessary
 * reloade instruction will be inserted after the given instruction.
 *
 * @param rc the regalloc context
 * @param vreg the virtual register
 * @param insn the instruction after which the reload insertion will
 * be inserted
 * @param distance the distance of the current instruction
 *
 * @return the hard register allocated if succeeds, 0 otherwise
 */
static JitReg
allocate_hreg(RegallocContext *rc, JitReg vreg, JitInsn *insn, int distance)
{
    const int kind = jit_reg_kind(vreg);
    const HardReg *hregs;
    unsigned hreg_num;
    JitReg hreg, vreg_to_reload = 0;
    int min_distance = distance, vr_distance;
    VirtualReg *vr = rc_get_vr(rc, vreg);
    unsigned i;

    bh_assert(kind < JIT_REG_KIND_L32);
    hregs = rc->hregs[kind];
    hreg_num = jit_cc_hreg_num(rc->cc, kind);

    if (hreg_num == 0)
    /* Unsupported hard register kind.  */
    {
        jit_set_last_error(rc->cc, "unsupported hard register kind");
        return 0;
    }

    if (vr->global_hreg)
    /* It has globally allocated register, we can only use it.  */
    {
        if ((vreg_to_reload = (rc_get_hr(rc, vr->global_hreg))->vreg))
            if (!reload_vreg(rc, vreg_to_reload, insn))
                return 0;

        return vr->global_hreg;
    }

    /* Use the last define-released register if its kind is correct and
       it's free so as to optimize for two-operand instructions.  */
    if (jit_reg_kind(rc->last_def_released_hreg) == kind
        && (rc_get_hr(rc, rc->last_def_released_hreg))->vreg == 0)
        return rc->last_def_released_hreg;

    /* No hint given, just try to pick any free register.  */
    for (i = 0; i < hreg_num; i++) {
        hreg = jit_reg_new(kind, i);

        if (jit_cc_is_hreg_fixed(rc->cc, hreg))
            continue;

        if (hregs[i].vreg == 0)
            /* Found a free one, return it.  */
            return hreg;
    }

    /* No free registers, need to spill and reload one.  */
    for (i = 0; i < hreg_num; i++) {
        if (jit_cc_is_hreg_fixed(rc->cc, jit_reg_new(kind, i)))
            continue;

        vr = rc_get_vr(rc, hregs[i].vreg);
        /* TODO: since the hregs[i] is in use, its distances should be valid */
        vr_distance = vr->distances ? uint_stack_top(vr->distances) : 0;

        if (vr_distance < min_distance) {
            min_distance = vr_distance;
            vreg_to_reload = hregs[i].vreg;
            hreg = jit_reg_new(kind, i);
        }
    }

    bh_assert(min_distance < distance);

    if (!reload_vreg(rc, vreg_to_reload, insn))
        return 0;

    return hreg;
}

/**
 * Allocate a hard register for the virtual register if not allocated
 * yet.  Necessary spill and reloade instructions will be inserted
 * before/after and after the given instruction.  This operation will
 * convert the virtual register's state from 1 or 3 to 2.
 *
 * @param rc the regalloc context
 * @param vreg the virtual register
 * @param insn the instruction after which the spill and reload
 * insertions will be inserted
 * @param distance the distance of the current instruction
 *
 * @return the hard register allocated to the virtual register if
 * succeeds, 0 otherwise
 */
static JitReg
allocate_for_vreg(RegallocContext *rc, JitReg vreg, JitInsn *insn, int distance)
{
    VirtualReg *vr = rc_get_vr(rc, vreg);

    if (vr->hreg)
        /* It has had a hard register, reuse it.  */
        return vr->hreg;

    /* Not allocated yet.  */
    if ((vr->hreg = allocate_hreg(rc, vreg, insn, distance)))
        (rc_get_hr(rc, vr->hreg))->vreg = vreg;

    return vr->hreg;
}

/**
 * Clobber live registers.
 *
 * @param rc the regalloc context
 * @param is_native whether it's native ABI or JITed ABI
 * @param insn the instruction after which the reload insertion will
 * be inserted
 *
 * @return true if succeeds, false otherwise
 */
static bool
clobber_live_regs(RegallocContext *rc, bool is_native, JitInsn *insn)
{
    unsigned i, j;

    for (i = JIT_REG_KIND_VOID; i < JIT_REG_KIND_L32; i++) {
        const unsigned hreg_num = jit_cc_hreg_num(rc->cc, i);

        for (j = 0; j < hreg_num; j++) {
            JitReg hreg = jit_reg_new(i, j);
            bool caller_saved =
                (is_native ? jit_cc_is_hreg_caller_saved_native(rc->cc, hreg)
                           : jit_cc_is_hreg_caller_saved_jitted(rc->cc, hreg));

            if (caller_saved && rc->hregs[i][j].vreg)
                if (!reload_vreg(rc, rc->hregs[i][j].vreg, insn))
                    return false;
        }
    }

    return true;
}

/**
 * Do local register allocation for the given basic block
 *
 * @param rc the regalloc context
 * @param basic_block the basic block
 * @param distance the distance of the last instruction of the basic block
 *
 * @return true if succeeds, false otherwise
 */
static bool
allocate_for_basic_block(RegallocContext *rc, JitBasicBlock *basic_block,
                         int distance)
{
    JitInsn *insn;

    JIT_FOREACH_INSN_REVERSE(basic_block, insn)
    {
#if WASM_ENABLE_SHARED_MEMORY != 0
        /* fence insn doesn't have any operand, hence, no regs involved */
        if (insn->opcode == JIT_OP_FENCE) {
            continue;
        }
#endif

        JitRegVec regvec = jit_insn_opnd_regs(insn);
        unsigned first_use = jit_insn_opnd_first_use(insn);
        unsigned i;
        JitReg *regp;

        distance--;

        JIT_REG_VEC_FOREACH_DEF(regvec, i, regp, first_use)
        if (is_alloc_candidate(rc->cc, *regp)) {
            const JitReg vreg = *regp;
            VirtualReg *vr = rc_get_vr(rc, vreg);

            if (!(*regp = allocate_for_vreg(rc, vreg, insn, distance)))
                return false;

            /* Spill the register if required.  */
            if (vr->slot && !spill_vreg(rc, vreg, insn))
                return false;

            bh_assert(uint_stack_top(vr->distances) == distance);
            uint_stack_pop(&vr->distances);
            /* Record the define-released hard register.  */
            rc->last_def_released_hreg = vr->hreg;
            /* Release the hreg and spill slot. */
            rc_free_spill_slot(rc, vr->slot);
            (rc_get_hr(rc, vr->hreg))->vreg = 0;
            vr->hreg = vr->slot = 0;
        }

        if (insn->opcode == JIT_OP_CALLBC) {
            if (!clobber_live_regs(rc, false, insn))
                return false;

            /* The exec_env_reg is implicitly used by the callee.  */
            if (!allocate_for_vreg(rc, rc->cc->exec_env_reg, insn, distance))
                return false;
        }
        else if (insn->opcode == JIT_OP_CALLNATIVE) {
            if (!clobber_live_regs(rc, true, insn))
                return false;
        }

        JIT_REG_VEC_FOREACH_USE(regvec, i, regp, first_use)
        if (is_alloc_candidate(rc->cc, *regp)) {
            if (!allocate_for_vreg(rc, *regp, insn, distance))
                return false;
        }

        JIT_REG_VEC_FOREACH_USE(regvec, i, regp, first_use)
        if (is_alloc_candidate(rc->cc, *regp)) {
            VirtualReg *vr = rc_get_vr(rc, *regp);
            bh_assert(uint_stack_top(vr->distances) == distance);
            uint_stack_pop(&vr->distances);
            /* be sure that the hreg exists and hasn't been spilled out */
            bh_assert(vr->hreg != 0);
            *regp = vr->hreg;
        }
    }

    return true;
}

bool
jit_pass_regalloc(JitCompContext *cc)
{
    RegallocContext rc = { 0 };
    unsigned label_index, end_label_index;
    JitBasicBlock *basic_block;
    VirtualReg *self_vr;
    bool retval = false;

    if (!rc_init(&rc, cc))
        return false;

    /* NOTE: don't allocate new virtual registers during allocation
       because the rc->vregs array is fixed size.  */

    /* TODO: allocate hard registers for global virtual registers here.
       Currently, exec_env_reg is the only global virtual register.  */
    self_vr = rc_get_vr(&rc, cc->exec_env_reg);

    JIT_FOREACH_BLOCK_ENTRY_EXIT(cc, label_index, end_label_index, basic_block)
    {
        int distance;

        /* TODO: initialize hreg for live-out registers.  */
        self_vr->hreg = self_vr->global_hreg;
        (rc_get_hr(&rc, cc->exec_env_reg))->vreg = cc->exec_env_reg;

        /**
         * TODO: the allocation of a basic block keeps using vregs[]
         * and hregs[] from previous basic block
         */
        if ((distance = collect_distances(&rc, basic_block)) < 0)
            goto cleanup_and_return;

        if (!allocate_for_basic_block(&rc, basic_block, distance))
            goto cleanup_and_return;

        /* TODO: generate necessary spills for live-in registers.  */
    }

    retval = true;

cleanup_and_return:
    rc_destroy(&rc);

    return retval;
}
