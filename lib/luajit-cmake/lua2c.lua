--[[
  Copyright 2014 The Luvit Authors. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
s
]]
local src, gen = ...
local _, jit = pcall(require, "jit") if jit and jit.off then jit.off() end

local chunk = assert(loadfile(src, nil, '@'..src))
local bytecode = string.dump(chunk)

local function basename(name)
   local base = name
   if base:match "[/\\]" then
      base = name:match("^.*[/\\](.*)$")
   end
   base = base:gsub("^%.", "_")
   if base:match "%." then
      base = base:match("^(.*)%."):gsub("%.", "_")
   end
   return base
end

local function escapefn(name)
   return '"'..
      name:gsub('\\', '\\\\')
          :gsub('\n', '\\n')
          :gsub('\r', '\\r')
          :gsub('"', '\\"')..'"'
end

local function write_chunk(s)
   local t = { "{\n       " };
   local cc = 7
   for i = 1, #s do
      local c = string.byte(s, i, i)
      local ss = (" 0x%X"):format(c)
      if cc + #ss > 77 then
         t[#t+1] = "\n       "
         t[#t+1] = ss
         cc = 7 + #ss
         if i ~= #s then
            t[#t+1] = ","
            cc = cc + 1
         end
      else
         t[#t+1] = ss
         cc = cc + #ss
         if i ~= #s then
            t[#t+1] = ","
            cc = cc + 1
         end
      end
   end
   t[#t+1] = "\n    }"
   return (table.concat(t))
end

local function W(...)
   io.write(...)
   return W
end

io.output(gen)
W [[
/* generated source for Lua codes */

#ifndef LUA_LIB
# define LUA_LIB
#endif
#include <lua.h>
#include <lauxlib.h>

LUALIB_API int luaopen_]](basename(src))[[(lua_State *L) {
    size_t len = ]](#bytecode)[[;
    const char chunk[] = ]](write_chunk(bytecode))[[;

    if (luaL_loadbuffer(L, chunk, len, ]](escapefn(src))[[) != 0)
        lua_error(L);
    lua_insert(L, 1);
    lua_call(L, lua_gettop(L)-1, LUA_MULTRET);
    return lua_gettop(L);
}

]]
io.close()


