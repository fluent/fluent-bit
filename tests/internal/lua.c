/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_lua.h>
#include <lauxlib.h>
#include <lua.h>

#include "flb_tests_internal.h"
#include "mpack/mpack.h"
#include "msgpack/object.h"
#include "msgpack/pack.h"
#include "msgpack/sbuffer.h"

/* Helper lua function which returns a string representation of lua objects.
 * Tables are stringified in key order (lua table iteration order is not deterministic. */
const char lua_stringify_object_helper[] = (""
"function stringify(o)\n"
"   if type(o) == 'table' then\n"
"      local keys = {}\n"
"      for k in pairs(o) do table.insert(keys, k) end\n"
"      table.sort(keys)\n"
"      local s = '{ '\n"
"      for _,k in ipairs(keys) do\n"
"         local v = o[k]\n"
"         s = s .. '['..k..'] = ' .. stringify(v) .. ' '\n"
"      end\n"
"      return s .. '}'\n"
"   else\n"
"      return tostring(o)\n"
"   end\n"
"end\n");

static lua_State *lua_setup(const char *script)
{
    lua_State *ret = luaL_newstate();
    if (!ret) {
        flb_error("[lua] error creating new context");
        return NULL;
    }
    luaL_openlibs(ret);
    luaL_loadstring(ret, lua_stringify_object_helper);
    if (lua_pcall(ret, 0, 0, 0)) {
        flb_error("[lua] error executing stringify helper script");
        lua_close(ret);
        return NULL;
    }
    if (script) {
        luaL_loadstring(ret, script);
        if (lua_pcall(ret, 0, 0, 0)) {
            flb_error("[lua] error executing test script");
            lua_close(ret);
            return NULL;
        }
    }
    return ret;
}

static void check_equals(lua_State *l, const char *expected)
{
    /* push the stringify function on the stack */
    lua_getglobal(l, "stringify");
    /* swap the top two elements of the stack, so that the function is below the arg */ 
    lua_insert(l, -2);
    /* call the function */
    if (lua_pcall(l, 1, 1, 0)) {
        flb_error("[lua] error calling stringify helper function");
        return;
    }
    const char *result = lua_tostring(l, -1);
    TEST_CHECK(strcmp(result, expected) == 0);
    TEST_MSG("Expected: %s", expected);
    TEST_MSG("Actual:   %s", result);
    /* remove the result */
    lua_pop(l, 1);
}

static void test_is_valid_func()
{
    lua_State *l = lua_setup(NULL);
    TEST_CHECK(flb_lua_is_valid_func(l, "invalid_function") == false);
    TEST_CHECK(flb_lua_is_valid_func(l, "stringify") == true);
    lua_close(l);
}

static void test_pushtimetable()
{
    lua_State *l = lua_setup(NULL);
    struct flb_time t = {{ 5, 6 }};
    flb_lua_pushtimetable(l, &t);
    check_equals(l, "{ [nsec] = 6 [sec] = 5 }");
    t.tm.tv_nsec = 7;
    t.tm.tv_sec = 8;
    flb_lua_pushtimetable(l, &t);
    check_equals(l, "{ [nsec] = 7 [sec] = 8 }");
    lua_close(l);
}

static void test_pushmsgpack()
{
    msgpack_packer pck;
    msgpack_sbuffer sbuf;
    msgpack_unpacked msg;
    lua_State *l = lua_setup(NULL);

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&pck, 3);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str_with_body(&pck, "key", 3);
    msgpack_pack_str_with_body(&pck, "value", 5);
    msgpack_pack_str_with_body(&pck, "msgpack-str", 11);
    msgpack_pack_int(&pck, 4);

    msgpack_unpacked_init(&msg);
    msgpack_unpack_next(&msg, sbuf.data, sbuf.size, NULL);
    flb_lua_pushmsgpack(l, &msg.data);
    check_equals(l, "{ [1] = { [key] = value } [2] = msgpack-str [3] = 4 }");

    msgpack_unpacked_destroy(&msg);
    msgpack_sbuffer_destroy(&sbuf);
    lua_close(l);
}

static void test_pushmpack()
{
    msgpack_packer pck;
    msgpack_sbuffer sbuf;
    mpack_reader_t reader;
    lua_State *l = lua_setup(NULL);

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&pck, 3);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str_with_body(&pck, "key", 3);
    msgpack_pack_str_with_body(&pck, "value", 5);
    msgpack_pack_str_with_body(&pck, "msgpack-str", 11);
    msgpack_pack_int(&pck, 4);

    mpack_reader_init_data(&reader, sbuf.data, sbuf.size);
    flb_lua_pushmpack(l, &reader);
    check_equals(l, "{ [1] = { [key] = value } [2] = msgpack-str [3] = 4 }");

    msgpack_sbuffer_destroy(&sbuf);
    lua_close(l);
}

static void test_tomsgpack()
{
    const char expected[] = "[{\"key\"=>\"value\"}, \"msgpack-str\", 4]";
    char buf[256];
    msgpack_packer pck;
    msgpack_sbuffer sbuf;
    msgpack_unpacked msg;
    struct flb_lua_l2c_config l2cc;
    lua_State *l = lua_setup("obj = {{['key']='value'},'msgpack-str',4}");

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    mk_list_init(&l2cc.l2c_types);
    l2cc.l2c_types_num = 0;

    lua_getglobal(l, "obj");
    flb_lua_tomsgpack(l, &pck, 0, &l2cc);

    msgpack_unpacked_init(&msg);
    msgpack_unpack_next(&msg, sbuf.data, sbuf.size, NULL);
    msgpack_object_print_buffer(buf, sizeof(buf), msg.data);

    TEST_CHECK(strcmp(buf, expected) == 0);
    TEST_MSG("Expected: %s", expected);
    TEST_MSG("Actual:   %s", buf);

    msgpack_unpacked_destroy(&msg);
    msgpack_sbuffer_destroy(&sbuf);
    lua_close(l);
}

static void test_tompack()
{
    const char expected[] = "[{\"key\"=>\"value\"}, \"msgpack-str\", 4]";
    char buf[256];
    char printbuf[256];
    mpack_writer_t writer;
    msgpack_unpacked msg;
    struct flb_lua_l2c_config l2cc;
    lua_State *l = lua_setup("obj = {{['key']='value'},'msgpack-str',4}");

    mpack_writer_init(&writer, buf, sizeof(buf));
    mk_list_init(&l2cc.l2c_types);
    l2cc.l2c_types_num = 0;

    lua_getglobal(l, "obj");
    flb_lua_tompack(l, &writer, 0, &l2cc);

    msgpack_unpacked_init(&msg);
    msgpack_unpack_next(&msg, writer.buffer, writer.position - writer.buffer, NULL);
    msgpack_object_print_buffer(printbuf, sizeof(printbuf), msg.data);

    TEST_CHECK(strcmp(printbuf, expected) == 0);
    TEST_MSG("Expected: %s", expected);
    TEST_MSG("Actual:   %s", buf);

    msgpack_unpacked_destroy(&msg);
    lua_close(l);
}

TEST_LIST = {
    { "lua_is_valid_func" , test_is_valid_func},
    { "lua_pushtimetable" , test_pushtimetable},
    { "lua_pushmsgpack" , test_pushmsgpack },
    { "lua_pushmpack" , test_pushmpack },
    { "lua_tomsgpack" , test_tomsgpack },
    { "lua_tompack" , test_tompack },
    { 0 }
};
