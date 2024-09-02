#include "cfl_to_lua.h"


void push_string(lua_State *L, const char *str, size_t size)
{
    lua_pushlstring(L, str, size);
}

void push_array(lua_State *L, struct cfl_array *array)
{
    int i;
    struct cfl_variant *entry;

    lua_createtable(L, array->entry_count, 0);

    for (i = 0; i < array->entry_count; i++) {
        entry = array->entries[i];
        push_variant(L, entry);
        lua_rawseti(L, -2, i + 1);
    }
}

void push_kvlist(lua_State *L, struct cfl_kvlist *kvlist)
{
    struct cfl_list *head;
    struct cfl_list *list;
    struct cfl_kvpair *kvpair;

    list = &kvlist->list;

    lua_createtable(L, 0, cfl_list_size(list));

    cfl_list_foreach(head, list)
    {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        push_string(L, kvpair->key, cfl_sds_len(kvpair->key));
        push_variant(L, kvpair->val);

        lua_settable(L, -3);
    }
}

void push_timestamp_as_table(lua_State *L, uint64_t timestamp)
{
    lua_createtable(L, 0, 2);
    lua_pushinteger(L, timestamp / 1000000);
    lua_setfield(L, -2, "millis");
    lua_pushinteger(L, timestamp % 1000000);
    lua_setfield(L, -2, "nanos");
}

void push_timestamp_as_string(lua_State *L, uint64_t timestamp)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%" PRIu64, timestamp);
    lua_pushstring(L, buf);
}

void push_variant(lua_State *L, struct cfl_variant *variant)
{
    int type = variant->type;

    switch (type) {
    case CFL_VARIANT_STRING:
        push_string(L, variant->data.as_string, cfl_variant_size_get(variant));
        break;
    case CFL_VARIANT_BOOL:
        lua_pushboolean(L, variant->data.as_bool);
        break;
    case CFL_VARIANT_INT:
        lua_pushinteger(L, variant->data.as_int64);
        break;
    case CFL_VARIANT_UINT:
        lua_pushinteger(L, variant->data.as_uint64);
        break;
    case CFL_VARIANT_DOUBLE:
        lua_pushnumber(L, variant->data.as_double);
        break;
    case CFL_VARIANT_ARRAY:
        push_array(L, variant->data.as_array);
        break;
    case CFL_VARIANT_KVLIST:
        push_kvlist(L, variant->data.as_kvlist);
        break;
    case CFL_VARIANT_BYTES:
        push_string(L, variant->data.as_bytes, cfl_variant_size_get(variant));
        break;
    default:
        /* unsupported type, push nil */
        lua_pushnil(L);
        break;
    }
}
