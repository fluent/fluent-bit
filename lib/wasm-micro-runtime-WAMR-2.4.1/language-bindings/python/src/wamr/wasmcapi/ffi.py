# -*- coding: utf-8 -*-
#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=missing-module-docstring

import ctypes as c
import os
from pathlib import Path
import sys

#
# Prologue. Dependencies of binding
#

# how to open the library file of WAMR

if sys.platform == "linux":
    BUILDING_DIR = "product-mini/platforms/linux/build"
    LIBRARY_NAME = "libiwasm.so"
elif sys.platform == "win32":
    BUILDING_DIR = "product-mini/platforms/windows/build"
    LIBRARY_NAME = "iwasm.dll"
elif sys.platform == "darwin":
    BUILDING_DIR = "product-mini/platforms/darwin/build"
    LIBRARY_NAME = "libiwasm.dylib"
else:
    raise RuntimeError(f"unsupported platform `{sys.platform}`")

# FIXME: should load libiwasm.so from current system library path
current_file = Path(__file__)
if current_file.is_symlink():
    current_file = Path(os.readlink(current_file))
current_dir = current_file.parent.resolve()
root_dir = current_dir.parents[4].resolve()
wamr_dir = root_dir.resolve()
if not wamr_dir.exists():
    raise RuntimeError(f"not found the repo of wasm-micro-runtime under {root_dir}")

libpath = wamr_dir.joinpath(BUILDING_DIR).joinpath(LIBRARY_NAME).resolve()
if not libpath.exists():
    raise RuntimeError(f"not found precompiled wamr library at {libpath}")

print(f"loading WAMR library from {libpath} ...")
libiwasm = c.cdll.LoadLibrary(libpath)


class wasm_ref_t(c.Structure):
    # pylint: disable=invalid-name
    pass


class wasm_val_union(c.Union):
    # pylint: disable=invalid-name
    _fields_ = [
        ("i32", c.c_int32),
        ("i64", c.c_int64),
        ("f32", c.c_float),
        ("f64", c.c_double),
        ("ref", c.POINTER(wasm_ref_t)),
    ]


class wasm_val_t(c.Structure):
    # pylint: disable=invalid-name
    _fields_ = [
        ("kind", c.c_uint8),
        ("of", wasm_val_union),
    ]


def dereference(p):
    # pylint: disable=protected-access
    if not isinstance(p, c._Pointer):
        raise RuntimeError("not a pointer")
    return p.contents


# HELPERs
def create_null_pointer(struct_type):
    return c.POINTER(struct_type)()


def is_null_pointer(c_pointer):
    # pylint: disable=protected-access
    if isinstance(c_pointer, c._Pointer):
        return False if c_pointer else True
    else:
        raise RuntimeError("not a pointer")


def wasm_vec_to_list(vec):
    """
    Converts a vector or a POINTER(vector) to a list
    vector of type pointers -> list of type pointers
    """
    known_vec_type = [
        wasm_byte_vec_t,
        wasm_valtype_vec_t,
        wasm_functype_vec_t,
        wasm_globaltype_vec_t,
        wasm_tabletype_vec_t,
        wasm_memorytype_vec_t,
        wasm_externtype_vec_t,
        wasm_importtype_vec_t,
        wasm_exporttype_vec_t,
        wasm_val_vec_t,
        wasm_frame_vec_t,
        wasm_extern_vec_t,
    ]
    known_vec_pointer_type = [POINTER(vec_type) for vec_type in known_vec_type]

    if any([isinstance(vec, pointer_type) for pointer_type in known_vec_pointer_type]):
        vec = dereference(vec)
        return [vec.data[i] for i in range(vec.num_elems)]
    elif any([isinstance(vec, vec_type) for vec_type in known_vec_type]):
        return [vec.data[i] for i in range(vec.num_elems)]
    else:
        raise RuntimeError("not a known vector type")


def list_to_carray(elem_type, *args):
    """
    Converts a python list into a C array
    """
    data = (elem_type * len(args))(*args)
    return data


def load_module_file(wasm_content):
    binary = wasm_byte_vec_t()
    wasm_byte_vec_new_uninitialized(binary, len(wasm_content))
    # has to use malloced memory.
    c.memmove(binary.data, wasm_content, len(wasm_content))
    binary.num_elems = len(wasm_content)
    return binary


#
# Enhancment of binding
#

from .binding import *

# Built-in functions for Structure


wasm_finalizer = CFUNCTYPE(None, c_void_p)


def __repr_wasm_limits_t(self):
    return f"{self.min:#x} {self.max:#x}"


# overwrite
wasm_limits_t.__repr__ = __repr_wasm_limits_t


def __compare_wasm_valtype_t(self, other):
    if not isinstance(other, wasm_valtype_t):
        return False

    return wasm_valtype_kind(byref(self)) == wasm_valtype_kind(byref(other))


def __repr_wasm_valtype_t(self):
    val_kind = wasm_valtype_kind(byref(self))
    if WASM_I32 == val_kind:
        return "i32"
    elif WASM_I64 == val_kind:
        return "i64"
    elif WASM_F32 == val_kind:
        return "f32"
    elif WASM_F64 == val_kind:
        return "f64"
    elif WASM_FUNCREF == val_kind:
        return "funcref"
    else:
        return "externref"


wasm_valtype_t.__eq__ = __compare_wasm_valtype_t
wasm_valtype_t.__repr__ = __repr_wasm_valtype_t


def __compare_wasm_byte_vec_t(self, other):
    if not isinstance(other, wasm_byte_vec_t):
        return False

    if self.num_elems != other.num_elems:
        return False

    self_data = bytes(self.data[: self.num_elems])
    other_data = bytes(other.data[: other.num_elems])
    return self_data.decode() == other_data.decode()


def __repr_wasm_byte_vec_t(self):
    data = bytes(self.data[: self.num_elems])
    return data.decode() if self.size else ""


wasm_byte_vec_t.__eq__ = __compare_wasm_byte_vec_t
wasm_byte_vec_t.__repr__ = __repr_wasm_byte_vec_t


def __compare_wasm_functype_t(self, other):
    if not isinstance(other, wasm_functype_t):
        return False

    params1 = dereference(wasm_functype_params(byref(self)))
    params2 = dereference(wasm_functype_params(byref(other)))
    results1 = dereference(wasm_functype_results(byref(self)))
    results2 = dereference(wasm_functype_results(byref(other)))
    return params1 == params2 and results1 == results2


def __repr_wasm_functype_t(self):
    params = dereference(wasm_functype_params(byref(self)))
    results = dereference(wasm_functype_results(byref(self)))
    params = f" (params {params})" if params.size else ""
    results = f" (results {results})" if results.size else ""
    return f"(func{params}{results})"


wasm_functype_t.__eq__ = __compare_wasm_functype_t
wasm_functype_t.__repr__ = __repr_wasm_functype_t


def __compare_wasm_globaltype_t(self, other):
    if not isinstance(other, wasm_globaltype_t):
        return False

    content1 = dereference(wasm_globaltype_content(byref(self)))
    content2 = dereference(wasm_globaltype_content(byref(other)))
    mutability1 = wasm_globaltype_mutability(byref(self))
    mutability2 = wasm_globaltype_mutability(byref(other))
    return content1 == content2 and mutability1 == mutability2


def __repr_wasm_globaltype_t(self):
    mutability = f"{wasm_globaltype_mutability(byref(self))}"
    content = f"{dereference(wasm_globaltype_content(byref(self)))}"
    return f"(global{' mut ' if mutability else ' '}{content})"


wasm_globaltype_t.__eq__ = __compare_wasm_globaltype_t
wasm_globaltype_t.__repr__ = __repr_wasm_globaltype_t


def __compare_wasm_tabletype_t(self, other):
    if not isinstance(other, wasm_tabletype_t):
        return False

    element1 = dereference(wasm_tabletype_element(byref(self)))
    element2 = dereference(wasm_tabletype_element(byref(other)))
    limits1 = dereference(wasm_tabletype_limits(byref(self)))
    limits2 = dereference(wasm_tabletype_limits(byref(other)))
    return element1 == element2 and limits1 == limits2


def __repr_wasm_tabletype_t(self):
    element = dereference(wasm_tabletype_element(byref(self)))
    limit = dereference(wasm_tabletype_limits(byref(self)))
    return f"(table {limit} {element})"


wasm_tabletype_t.__eq__ = __compare_wasm_tabletype_t
wasm_tabletype_t.__repr__ = __repr_wasm_tabletype_t


def __compare_wasm_memorytype_t(self, other):
    if not isinstance(other, wasm_memorytype_t):
        return False

    limits1 = dereference(wasm_memorytype_limits(byref(self)))
    limits2 = dereference(wasm_memorytype_limits(byref(other)))
    return limits1 == limits2


def __repr_wasm_memorytype_t(self):
    limit = dereference(wasm_memorytype_limits(byref(self)))
    return f"(memory {limit})"


wasm_memorytype_t.__eq__ = __compare_wasm_memorytype_t
wasm_memorytype_t.__repr__ = __repr_wasm_memorytype_t


def __compare_wasm_externtype_t(self, other):
    if not isinstance(other, wasm_externtype_t):
        return False

    if wasm_externtype_kind(byref(self)) != wasm_externtype_kind(byref(other)):
        return False

    extern_kind = wasm_externtype_kind(byref(self))
    if WASM_EXTERN_FUNC == extern_kind:
        return dereference(wasm_externtype_as_functype(self)) == dereference(
            wasm_externtype_as_functype(other)
        )
    elif WASM_EXTERN_GLOBAL == extern_kind:
        return dereference(wasm_externtype_as_globaltype(self)) == dereference(
            wasm_externtype_as_globaltype(other)
        )
    elif WASM_EXTERN_MEMORY == extern_kind:
        return dereference(wasm_externtype_as_memorytype(self)) == dereference(
            wasm_externtype_as_memorytype(other)
        )
    elif WASM_EXTERN_TABLE == extern_kind:
        return dereference(wasm_externtype_as_tabletype(self)) == dereference(
            wasm_externtype_as_tabletype(other)
        )
    else:
        raise RuntimeError("not a valid wasm_externtype_t")


def __repr_wasm_externtype_t(self):
    extern_kind = wasm_externtype_kind(byref(self))
    if WASM_EXTERN_FUNC == extern_kind:
        return str(dereference(wasm_externtype_as_functype(byref(self))))
    elif WASM_EXTERN_GLOBAL == extern_kind:
        return str(dereference(wasm_externtype_as_globaltype(byref(self))))
    elif WASM_EXTERN_MEMORY == extern_kind:
        return str(dereference(wasm_externtype_as_memorytype(byref(self))))
    elif WASM_EXTERN_TABLE == extern_kind:
        return str(dereference(wasm_externtype_as_tabletype(byref(self))))
    else:
        raise RuntimeError("not a valid wasm_externtype_t")


wasm_externtype_t.__eq__ = __compare_wasm_externtype_t
wasm_externtype_t.__repr__ = __repr_wasm_externtype_t


def __compare_wasm_importtype_t(self, other):
    if not isinstance(other, wasm_importtype_t):
        return False

    if dereference(wasm_importtype_module(self)) != dereference(
        wasm_importtype_module(other)
    ):
        return False

    if dereference(wasm_importtype_name(self)) != dereference(
        wasm_importtype_name(other)
    ):
        return False

    self_type = dereference(wasm_importtype_type(byref(self)))
    other_type = dereference(wasm_importtype_type(byref(other)))
    return self_type == other_type


def __repr_wasm_importtype_t(self):
    module = wasm_importtype_module(byref(self))
    name = wasm_importtype_name(byref(self))
    extern_type = wasm_importtype_type(byref(self))
    return f'(import "{dereference(module)}" "{dereference(name)}" {dereference(extern_type)})'


wasm_importtype_t.__eq__ = __compare_wasm_importtype_t
wasm_importtype_t.__repr__ = __repr_wasm_importtype_t


def __compare_wasm_exporttype_t(self, other):
    if not isinstance(other, wasm_exporttype_t):
        return False

    self_name = dereference(wasm_exporttype_name(byref(self)))
    other_name = dereference(wasm_exporttype_name(byref(other)))
    if self_name != other_name:
        return False

    self_type = dereference(wasm_exporttype_type(byref(self)))
    other_type = dereference(wasm_exporttype_type(byref(other)))
    return self_type == other_type


def __repr_wasm_exporttype_t(self):
    name = wasm_exporttype_name(byref(self))
    extern_type = wasm_exporttype_type(byref(self))
    return f'(export "{dereference(name)}" {dereference(extern_type)})'


wasm_exporttype_t.__eq__ = __compare_wasm_exporttype_t
wasm_exporttype_t.__repr__ = __repr_wasm_exporttype_t


def __compare_wasm_val_t(self, other):
    if not isinstance(other, wasm_val_t):
        return False

    if self.kind != other.kind:
        return False

    if WASM_I32 == self.kind:
        return self.of.i32 == other.of.i32
    elif WASM_I64 == self.kind:
        return self.of.i64 == other.of.i64
    elif WASM_F32 == self.kind:
        return self.of.f32 == other.of.f32
    elif WASM_F64 == self.kind:
        return self.of.f64 == other.of.f64
    elif WASM_EXTERNREF == self.kind:
        raise RuntimeError("FIXME")
    else:
        raise RuntimeError("not a valid val kind")


def __repr_wasm_val_t(self):
    if WASM_I32 == self.kind:
        return f"i32 {self.of.i32}"
    elif WASM_I64 == self.kind:
        return f"i64 {self.of.i64}"
    elif WASM_F32 == self.kind:
        return f"f32 {self.of.f32}"
    elif WASM_F64 == self.kind:
        return f"f64 {self.of.f64}"
    elif WASM_EXTERNREF == self.kind:
        return f"externref {self.of.ref}"
    else:
        raise RuntimeError("not a valid val kind")


wasm_val_t.__repr__ = __repr_wasm_val_t
wasm_val_t.__eq__ = __compare_wasm_val_t


def __repr_wasm_trap_t(self):
    message = wasm_message_t()
    wasm_trap_message(self, message)
    return f'(trap "{str(message)}")'


wasm_trap_t.__repr__ = __repr_wasm_trap_t


def __repr_wasm_frame_t(self):
    instance = wasm_frame_instance(self)
    module_offset = wasm_frame_module_offset(self)
    func_index = wasm_frame_func_index(self)
    func_offset = wasm_frame_func_offset(self)
    return f"> module:{module_offset:#x} => func#{func_index:#x}.{func_offset:#x}"


wasm_frame_t.__repr__ = __repr_wasm_frame_t


def __repr_wasm_module_t(self):
    imports = wasm_importtype_vec_t()
    wasm_module_imports(self, imports)

    exports = wasm_exporttype_vec_t()
    wasm_module_exports(self, exports)

    ret = "(module"
    ret += str(imports).replace("(import", "\n  (import")
    ret += str(exports).replace("(export", "\n  (export")
    ret += "\n)"
    return ret


wasm_module_t.__repr__ = __repr_wasm_module_t


def __repr_wasm_instance_t(self):
    exports = wasm_extern_vec_t()
    wasm_instance_exports(self, exports)

    ret = "(instance"
    ret += str(exports).replace("(export", "\n (export")
    ret += "\n)"
    return ret


wasm_instance_t.__repr__ = __repr_wasm_instance_t


def __repr_wasm_func_t(self):
    ft = wasm_func_type(self)
    return f"{str(dereference(ft))[:-1]} ... )"


wasm_func_t.__repr__ = __repr_wasm_func_t


def __repr_wasm_global_t(self):
    gt = wasm_global_type(self)
    return f"{str(dereference(gt))[:-1]} ... )"


wasm_global_t.__repr__ = __repr_wasm_global_t


def __repr_wasm_table_t(self):
    tt = wasm_table_type(self)
    return f"{str(dereference(tt))[:-1]} ... )"


wasm_table_t.__repr__ = __repr_wasm_table_t


def __repr_wasm_memory_t(self):
    mt = wasm_memory_type(self)
    return f"{str(dereference(mt))[:-1]} ... )"


wasm_memory_t.__repr__ = __repr_wasm_memory_t


def __repr_wasm_extern_t(self):
    ext_type = wasm_extern_type(self)
    ext_kind = wasm_extern_kind(self)

    ret = "(export "
    if WASM_EXTERN_FUNC == ext_kind:
        ft = wasm_externtype_as_functype(ext_type)
        ret += str(dereference(ft))
    elif WASM_EXTERN_GLOBAL == ext_kind:
        gt = wasm_externtype_as_globaltype(ext_type)
        ret += str(dereference(gt))
    elif WASM_EXTERN_MEMORY == ext_kind:
        mt = wasm_externtype_as_memorytype(ext_type)
        ret += str(dereference(mt))
    elif WASM_EXTERN_TABLE == ext_kind:
        tt = wasm_externtype_as_tabletype(ext_type)
        ret += str(dereference(tt))
    else:
        raise RuntimeError("not a valid extern kind")
    ret += ")"
    return ret


wasm_extern_t.__repr__ = __repr_wasm_extern_t


# Function Types construction short-hands
def wasm_name_new_from_string(s):
    name = wasm_name_t()
    data = ((c.c_ubyte) * len(s)).from_buffer_copy(s.encode())
    wasm_byte_vec_new(byref(name), len(s), data)
    return name


def __wasm_functype_new(param_list, result_list):
    def __list_to_wasm_valtype_vec(l):
        vec = wasm_valtype_vec_t()

        if not l:
            wasm_valtype_vec_new_empty(byref(vec))
        else:
            data_type = POINTER(wasm_valtype_t) * len(l)
            data = data_type()
            for i in range(len(l)):
                data[i] = l[i]
            wasm_valtype_vec_new(byref(vec), len(l), data)

        return vec

    params = __list_to_wasm_valtype_vec(param_list)
    results = __list_to_wasm_valtype_vec(result_list)
    return wasm_functype_new(byref(params), byref(results))


def wasm_functype_new_0_0():
    return __wasm_functype_new([], [])


def wasm_functype_new_1_0(p1):
    return __wasm_functype_new([p1], [])


def wasm_functype_new_2_0(p1, p2):
    return __wasm_functype_new([p1, p2], [])


def wasm_functype_new_3_0(p1, p2, p3):
    return __wasm_functype_new([p1, p2, p3], [])


def wasm_functype_new_0_1(r1):
    return __wasm_functype_new([], [r1])


def wasm_functype_new_1_1(p1, r1):
    return __wasm_functype_new([p1], [r1])


def wasm_functype_new_2_1(p1, p2, r1):
    return __wasm_functype_new([p1, p2], [r1])


def wasm_functype_new_3_1(p1, p2, p3, r1):
    return __wasm_functype_new([p1, p2, p3], [r1])


def wasm_limits_new(min, max):
    limit = wasm_limits_t()
    limit.min = min
    limit.max = max
    return c.pointer(limit)


def wasm_i32_val(i):
    v = wasm_val_t()
    v.kind = WASM_I32
    v.of.i32 = i
    return v


def wasm_i64_val(i):
    v = wasm_val_t()
    v.kind = WASM_I64
    v.of.i64 = i
    return v


def wasm_f32_val(z):
    v = wasm_val_t()
    v.kind = WASM_F32
    v.of.f32 = z
    return v


def wasm_f64_val(z):
    v = wasm_val_t()
    v.kind = WASM_F64
    v.of.f64 = z
    return v


def wasm_func_cb_decl(func):
    return wasm_func_callback_t(func)


def wasm_func_with_env_cb_decl(func):
    return wasm_func_callback_with_env_t(func)
