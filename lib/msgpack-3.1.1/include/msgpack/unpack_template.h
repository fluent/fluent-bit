/*
 * MessagePack unpacking routine template
 *
 * Copyright (C) 2008-2010 FURUHASHI Sadayuki
 *
 *    Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *    http://www.boost.org/LICENSE_1_0.txt)
 */

#ifndef msgpack_unpack_func
#error msgpack_unpack_func template is not defined
#endif

#ifndef msgpack_unpack_callback
#error msgpack_unpack_callback template is not defined
#endif

#ifndef msgpack_unpack_struct
#error msgpack_unpack_struct template is not defined
#endif

#ifndef msgpack_unpack_struct_decl
#define msgpack_unpack_struct_decl(name) msgpack_unpack_struct(name)
#endif

#ifndef msgpack_unpack_object
#error msgpack_unpack_object type is not defined
#endif

#ifndef msgpack_unpack_user
#error msgpack_unpack_user type is not defined
#endif

#ifndef USE_CASE_RANGE
#if !defined(_MSC_VER)
#define USE_CASE_RANGE
#endif
#endif

msgpack_unpack_struct_decl(_stack) {
    msgpack_unpack_object obj;
    size_t count;
    unsigned int ct;
    msgpack_unpack_object map_key;
};

msgpack_unpack_struct_decl(_context) {
    msgpack_unpack_user user;
    unsigned int cs;
    unsigned int trail;
    unsigned int top;
    /*
    msgpack_unpack_struct(_stack)* stack;
    unsigned int stack_size;
    msgpack_unpack_struct(_stack) embed_stack[MSGPACK_EMBED_STACK_SIZE];
    */
    msgpack_unpack_struct(_stack) stack[MSGPACK_EMBED_STACK_SIZE];
};


msgpack_unpack_func(void, _init)(msgpack_unpack_struct(_context)* ctx)
{
    ctx->cs = MSGPACK_CS_HEADER;
    ctx->trail = 0;
    ctx->top = 0;
    /*
    ctx->stack = ctx->embed_stack;
    ctx->stack_size = MSGPACK_EMBED_STACK_SIZE;
    */
    ctx->stack[0].obj = msgpack_unpack_callback(_root)(&ctx->user);
}

/*
msgpack_unpack_func(void, _destroy)(msgpack_unpack_struct(_context)* ctx)
{
    if(ctx->stack_size != MSGPACK_EMBED_STACK_SIZE) {
        free(ctx->stack);
    }
}
*/

msgpack_unpack_func(msgpack_unpack_object, _data)(msgpack_unpack_struct(_context)* ctx)
{
    return (ctx)->stack[0].obj;
}


msgpack_unpack_func(int, _execute)(msgpack_unpack_struct(_context)* ctx, const char* data, size_t len, size_t* off)
{
    assert(len >= *off);
    {
        const unsigned char* p = (unsigned char*)data + *off;
        const unsigned char* const pe = (unsigned char*)data + len;
        const void* n = NULL;

        unsigned int trail = ctx->trail;
        unsigned int cs = ctx->cs;
        unsigned int top = ctx->top;
        msgpack_unpack_struct(_stack)* stack = ctx->stack;
        /*
        unsigned int stack_size = ctx->stack_size;
        */
        msgpack_unpack_user* user = &ctx->user;

        msgpack_unpack_object obj;
        msgpack_unpack_struct(_stack)* c = NULL;

        int ret;

#define push_simple_value(func) \
        ret = msgpack_unpack_callback(func)(user, &obj); \
        if(ret < 0) { goto _failed; } \
        goto _push
#define push_fixed_value(func, arg) \
        ret = msgpack_unpack_callback(func)(user, arg, &obj); \
        if(ret < 0) { goto _failed; } \
        goto _push
#define push_variable_value(func, base, pos, len) \
        ret = msgpack_unpack_callback(func)(user, \
            (const char*)base, (const char*)pos, len, &obj); \
        if(ret < 0) { goto _failed; } \
        goto _push

#define again_fixed_trail(_cs, trail_len) \
        trail = trail_len; \
        cs = _cs; \
        goto _fixed_trail_again
#define again_fixed_trail_if_zero(_cs, trail_len, ifzero) \
        trail = trail_len; \
        if(trail == 0) { goto ifzero; } \
        cs = _cs; \
        goto _fixed_trail_again

#define start_container(func, count_, ct_) \
        if(top >= MSGPACK_EMBED_STACK_SIZE) { \
            ret = MSGPACK_UNPACK_NOMEM_ERROR; \
            goto _failed; \
        } /* FIXME */ \
        ret = msgpack_unpack_callback(func)(user, count_, &stack[top].obj); \
        if(ret < 0) { goto _failed; } \
        if((count_) == 0) { obj = stack[top].obj; goto _push; } \
        stack[top].ct = ct_; \
        stack[top].count = count_; \
        ++top; \
        goto _header_again

#define NEXT_CS(p) \
        ((unsigned int)*p & 0x1f)

#ifdef USE_CASE_RANGE
#define SWITCH_RANGE_BEGIN     switch(*p) {
#define SWITCH_RANGE(FROM, TO) case FROM ... TO:
#define SWITCH_RANGE_DEFAULT   default:
#define SWITCH_RANGE_END       }
#else
#define SWITCH_RANGE_BEGIN     { if(0) {
#define SWITCH_RANGE(FROM, TO) } else if(FROM <= *p && *p <= TO) {
#define SWITCH_RANGE_DEFAULT   } else {
#define SWITCH_RANGE_END       } }
#endif

        if(p == pe) { goto _out; }
        do {
            switch(cs) {
            case MSGPACK_CS_HEADER:
                SWITCH_RANGE_BEGIN
                SWITCH_RANGE(0x00, 0x7f)  // Positive Fixnum
                    push_fixed_value(_uint8, *(uint8_t*)p);
                SWITCH_RANGE(0xe0, 0xff)  // Negative Fixnum
                    push_fixed_value(_int8, *(int8_t*)p);
                SWITCH_RANGE(0xc0, 0xdf)  // Variable
                    switch(*p) {
                    case 0xc0:  // nil
                        push_simple_value(_nil);
                    //case 0xc1:  // string
                    //  again_terminal_trail(NEXT_CS(p), p+1);
                    case 0xc2:  // false
                        push_simple_value(_false);
                    case 0xc3:  // true
                        push_simple_value(_true);
                    case 0xc4: // bin 8
                    case 0xc5: // bin 16
                    case 0xc6: // bin 32
                        again_fixed_trail(NEXT_CS(p), 1 << (((unsigned int)*p) & 0x03));
                    case 0xc7: // ext 8
                    case 0xc8: // ext 16
                    case 0xc9: // ext 32
                        again_fixed_trail(NEXT_CS(p), 1 << ((((unsigned int)*p) + 1) & 0x03));
                    case 0xca:  // float
                    case 0xcb:  // double
                    case 0xcc:  // unsigned int  8
                    case 0xcd:  // unsigned int 16
                    case 0xce:  // unsigned int 32
                    case 0xcf:  // unsigned int 64
                    case 0xd0:  // signed int  8
                    case 0xd1:  // signed int 16
                    case 0xd2:  // signed int 32
                    case 0xd3:  // signed int 64
                        again_fixed_trail(NEXT_CS(p), 1 << (((unsigned int)*p) & 0x03));
                    case 0xd4:  // fixext 1
                    case 0xd5:  // fixext 2
                    case 0xd6:  // fixext 4
                    case 0xd7:  // fixext 8
                        again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE,
                            (1 << (((unsigned int)*p) & 0x03)) + 1, _ext_zero);
                    case 0xd8:  // fixext 16
                        again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE, 16+1, _ext_zero);

                    case 0xd9:  // str 8
                    case 0xda:  // str 16
                    case 0xdb:  // str 32
                        again_fixed_trail(NEXT_CS(p), 1 << ((((unsigned int)*p) & 0x03) - 1));
                    case 0xdc:  // array 16
                    case 0xdd:  // array 32
                    case 0xde:  // map 16
                    case 0xdf:  // map 32
                        again_fixed_trail(NEXT_CS(p), 2u << (((unsigned int)*p) & 0x01));
                    default:
                        ret = MSGPACK_UNPACK_PARSE_ERROR;
                        goto _failed;
                    }
                SWITCH_RANGE(0xa0, 0xbf)  // FixStr
                    again_fixed_trail_if_zero(MSGPACK_ACS_STR_VALUE, ((unsigned int)*p & 0x1f), _str_zero);
                SWITCH_RANGE(0x90, 0x9f)  // FixArray
                    start_container(_array, ((unsigned int)*p) & 0x0f, MSGPACK_CT_ARRAY_ITEM);
                SWITCH_RANGE(0x80, 0x8f)  // FixMap
                    start_container(_map, ((unsigned int)*p) & 0x0f, MSGPACK_CT_MAP_KEY);

                SWITCH_RANGE_DEFAULT
                    ret = MSGPACK_UNPACK_PARSE_ERROR;
                    goto _failed;
                SWITCH_RANGE_END
                // end MSGPACK_CS_HEADER


            _fixed_trail_again:
                ++p;
                // fallthrough

            default:
                if((size_t)(pe - p) < trail) { goto _out; }
                n = p;  p += trail - 1;
                switch(cs) {
                //case MSGPACK_CS_
                //case MSGPACK_CS_
                case MSGPACK_CS_FLOAT: {
                        union { uint32_t i; float f; } mem;
                        _msgpack_load32(uint32_t, n, &mem.i);
                        push_fixed_value(_float, mem.f); }
                case MSGPACK_CS_DOUBLE: {
                        union { uint64_t i; double f; } mem;
                        _msgpack_load64(uint64_t, n, &mem.i);
#if defined(TARGET_OS_IPHONE)
                    // ok
#elif defined(__arm__) && !(__ARM_EABI__) // arm-oabi
                        // https://github.com/msgpack/msgpack-perl/pull/1
                        mem.i = (mem.i & 0xFFFFFFFFUL) << 32UL | (mem.i >> 32UL);
#endif
                        push_fixed_value(_double, mem.f); }
                case MSGPACK_CS_UINT_8:
                    push_fixed_value(_uint8, *(uint8_t*)n);
                case MSGPACK_CS_UINT_16:{
                    uint16_t tmp;
                    _msgpack_load16(uint16_t,n,&tmp);
                    push_fixed_value(_uint16, tmp);
                }
                case MSGPACK_CS_UINT_32:{
                    uint32_t tmp;
                    _msgpack_load32(uint32_t,n,&tmp);
                    push_fixed_value(_uint32, tmp);
                }
                case MSGPACK_CS_UINT_64:{
                    uint64_t tmp;
                    _msgpack_load64(uint64_t,n,&tmp);
                    push_fixed_value(_uint64, tmp);
                }
                case MSGPACK_CS_INT_8:
                    push_fixed_value(_int8, *(int8_t*)n);
                case MSGPACK_CS_INT_16:{
                    int16_t tmp;
                    _msgpack_load16(int16_t,n,&tmp);
                    push_fixed_value(_int16, tmp);
                }
                case MSGPACK_CS_INT_32:{
                    int32_t tmp;
                    _msgpack_load32(int32_t,n,&tmp);
                    push_fixed_value(_int32, tmp);
                }
                case MSGPACK_CS_INT_64:{
                    int64_t tmp;
                    _msgpack_load64(int64_t,n,&tmp);
                    push_fixed_value(_int64, tmp);
                }
                case MSGPACK_CS_FIXEXT_1:
                    again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE, 1+1, _ext_zero);
                case MSGPACK_CS_FIXEXT_2:
                    again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE, 2+1, _ext_zero);
                case MSGPACK_CS_FIXEXT_4:
                    again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE, 4+1, _ext_zero);
                case MSGPACK_CS_FIXEXT_8:
                    again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE, 8+1, _ext_zero);
                case MSGPACK_CS_FIXEXT_16:
                    again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE, 16+1, _ext_zero);
                case MSGPACK_CS_STR_8:
                    again_fixed_trail_if_zero(MSGPACK_ACS_STR_VALUE, *(uint8_t*)n, _str_zero);
                case MSGPACK_CS_BIN_8:
                    again_fixed_trail_if_zero(MSGPACK_ACS_BIN_VALUE, *(uint8_t*)n, _bin_zero);
                case MSGPACK_CS_EXT_8:
                    again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE, (*(uint8_t*)n) + 1, _ext_zero);
                case MSGPACK_CS_STR_16:{
                    uint16_t tmp;
                    _msgpack_load16(uint16_t,n,&tmp);
                    again_fixed_trail_if_zero(MSGPACK_ACS_STR_VALUE, tmp, _str_zero);
                }
                case MSGPACK_CS_BIN_16:{
                    uint16_t tmp;
                    _msgpack_load16(uint16_t,n,&tmp);
                    again_fixed_trail_if_zero(MSGPACK_ACS_BIN_VALUE, tmp, _bin_zero);
                }
                case MSGPACK_CS_EXT_16:{
                    uint16_t tmp;
                    _msgpack_load16(uint16_t,n,&tmp);
                    again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE, tmp + 1, _ext_zero);
                }
                case MSGPACK_CS_STR_32:{
                    uint32_t tmp;
                    _msgpack_load32(uint32_t,n,&tmp);
                    again_fixed_trail_if_zero(MSGPACK_ACS_STR_VALUE, tmp, _str_zero);
                }
                case MSGPACK_CS_BIN_32:{
                    uint32_t tmp;
                    _msgpack_load32(uint32_t,n,&tmp);
                    again_fixed_trail_if_zero(MSGPACK_ACS_BIN_VALUE, tmp, _bin_zero);
                }
                case MSGPACK_CS_EXT_32:{
                    uint32_t tmp;
                    _msgpack_load32(uint32_t,n,&tmp);
                    again_fixed_trail_if_zero(MSGPACK_ACS_EXT_VALUE, tmp + 1, _ext_zero);
                }
                case MSGPACK_ACS_STR_VALUE:
                _str_zero:
                    push_variable_value(_str, data, n, trail);
                case MSGPACK_ACS_BIN_VALUE:
                _bin_zero:
                    push_variable_value(_bin, data, n, trail);
                case MSGPACK_ACS_EXT_VALUE:
                _ext_zero:
                    push_variable_value(_ext, data, n, trail);

                case MSGPACK_CS_ARRAY_16:{
                    uint16_t tmp;
                    _msgpack_load16(uint16_t,n,&tmp);
                    start_container(_array, tmp, MSGPACK_CT_ARRAY_ITEM);
                }
                case MSGPACK_CS_ARRAY_32:{
                    /* FIXME security guard */
                    uint32_t tmp;
                    _msgpack_load32(uint32_t,n,&tmp);
                    start_container(_array, tmp, MSGPACK_CT_ARRAY_ITEM);
                }

                case MSGPACK_CS_MAP_16:{
                    uint16_t tmp;
                    _msgpack_load16(uint16_t,n,&tmp);
                    start_container(_map, tmp, MSGPACK_CT_MAP_KEY);
                }
                case MSGPACK_CS_MAP_32:{
                    /* FIXME security guard */
                    uint32_t tmp;
                    _msgpack_load32(uint32_t,n,&tmp);
                    start_container(_map, tmp, MSGPACK_CT_MAP_KEY);
                }

                default:
                    ret = MSGPACK_UNPACK_PARSE_ERROR;
                    goto _failed;
                }
            }

    _push:
        if(top == 0) { goto _finish; }
        c = &stack[top-1];
        switch(c->ct) {
        case MSGPACK_CT_ARRAY_ITEM:
            ret = msgpack_unpack_callback(_array_item)(user, &c->obj, obj); \
            if(ret < 0) { goto _failed; }
            if(--c->count == 0) {
                obj = c->obj;
                --top;
                /*printf("stack pop %d\n", top);*/
                goto _push;
            }
            goto _header_again;
        case MSGPACK_CT_MAP_KEY:
            c->map_key = obj;
            c->ct = MSGPACK_CT_MAP_VALUE;
            goto _header_again;
        case MSGPACK_CT_MAP_VALUE:
            ret = msgpack_unpack_callback(_map_item)(user, &c->obj, c->map_key, obj); \
            if(ret < 0) { goto _failed; }
            if(--c->count == 0) {
                obj = c->obj;
                --top;
                /*printf("stack pop %d\n", top);*/
                goto _push;
            }
            c->ct = MSGPACK_CT_MAP_KEY;
            goto _header_again;

        default:
            ret = MSGPACK_UNPACK_PARSE_ERROR;
            goto _failed;
        }

    _header_again:
            cs = MSGPACK_CS_HEADER;
            ++p;
        } while(p != pe);
        goto _out;


    _finish:
        stack[0].obj = obj;
        ++p;
        ret = 1;
        /*printf("-- finish --\n"); */
        goto _end;

    _failed:
        /*printf("** FAILED **\n"); */
        goto _end;

    _out:
        ret = 0;
        goto _end;

    _end:
        ctx->cs = cs;
        ctx->trail = trail;
        ctx->top = top;
        *off = (size_t)(p - (const unsigned char*)data);

        return ret;
    }
}

#undef msgpack_unpack_func
#undef msgpack_unpack_callback
#undef msgpack_unpack_struct
#undef msgpack_unpack_object
#undef msgpack_unpack_user

#undef push_simple_value
#undef push_fixed_value
#undef push_variable_value
#undef again_fixed_trail
#undef again_fixed_trail_if_zero
#undef start_container

#undef NEXT_CS

#undef SWITCH_RANGE_BEGIN
#undef SWITCH_RANGE
#undef SWITCH_RANGE_DEFAULT
#undef SWITCH_RANGE_END
