# -*- coding: utf-8 -*-
#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
#It is a generated file. DO NOT EDIT.
#
from ctypes import *

from .ffi import dereference, libiwasm, wasm_ref_t, wasm_val_t


wasm_byte_t = c_ubyte

class wasm_byte_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(wasm_byte_t)),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_byte_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(self.data[i])
                ret += " "
        return ret



def wasm_byte_vec_new_empty(arg0):
    _wasm_byte_vec_new_empty = libiwasm.wasm_byte_vec_new_empty
    _wasm_byte_vec_new_empty.restype = None
    _wasm_byte_vec_new_empty.argtypes = [POINTER(wasm_byte_vec_t)]
    return _wasm_byte_vec_new_empty(arg0)

def wasm_byte_vec_new_uninitialized(arg0,arg1):
    _wasm_byte_vec_new_uninitialized = libiwasm.wasm_byte_vec_new_uninitialized
    _wasm_byte_vec_new_uninitialized.restype = None
    _wasm_byte_vec_new_uninitialized.argtypes = [POINTER(wasm_byte_vec_t),c_size_t]
    return _wasm_byte_vec_new_uninitialized(arg0,arg1)

def wasm_byte_vec_new(arg0,arg1,arg2):
    _wasm_byte_vec_new = libiwasm.wasm_byte_vec_new
    _wasm_byte_vec_new.restype = None
    _wasm_byte_vec_new.argtypes = [POINTER(wasm_byte_vec_t),c_size_t,POINTER(wasm_byte_t)]
    return _wasm_byte_vec_new(arg0,arg1,arg2)

def wasm_byte_vec_copy(arg0,arg1):
    _wasm_byte_vec_copy = libiwasm.wasm_byte_vec_copy
    _wasm_byte_vec_copy.restype = None
    _wasm_byte_vec_copy.argtypes = [POINTER(wasm_byte_vec_t),POINTER(wasm_byte_vec_t)]
    return _wasm_byte_vec_copy(arg0,arg1)

def wasm_byte_vec_delete(arg0):
    _wasm_byte_vec_delete = libiwasm.wasm_byte_vec_delete
    _wasm_byte_vec_delete.restype = None
    _wasm_byte_vec_delete.argtypes = [POINTER(wasm_byte_vec_t)]
    return _wasm_byte_vec_delete(arg0)

wasm_name_t = wasm_byte_vec_t

class wasm_config_t(Structure):
    pass

def wasm_config_delete(arg0):
    _wasm_config_delete = libiwasm.wasm_config_delete
    _wasm_config_delete.restype = None
    _wasm_config_delete.argtypes = [POINTER(wasm_config_t)]
    return _wasm_config_delete(arg0)

def wasm_config_new():
    _wasm_config_new = libiwasm.wasm_config_new
    _wasm_config_new.restype = POINTER(wasm_config_t)
    _wasm_config_new.argtypes = None
    return _wasm_config_new()

class wasm_engine_t(Structure):
    pass

def wasm_engine_delete(arg0):
    _wasm_engine_delete = libiwasm.wasm_engine_delete
    _wasm_engine_delete.restype = None
    _wasm_engine_delete.argtypes = [POINTER(wasm_engine_t)]
    return _wasm_engine_delete(arg0)

def wasm_engine_new():
    _wasm_engine_new = libiwasm.wasm_engine_new
    _wasm_engine_new.restype = POINTER(wasm_engine_t)
    _wasm_engine_new.argtypes = None
    return _wasm_engine_new()

def wasm_engine_new_with_config(arg0):
    _wasm_engine_new_with_config = libiwasm.wasm_engine_new_with_config
    _wasm_engine_new_with_config.restype = POINTER(wasm_engine_t)
    _wasm_engine_new_with_config.argtypes = [POINTER(wasm_config_t)]
    return _wasm_engine_new_with_config(arg0)

class wasm_store_t(Structure):
    pass

def wasm_store_delete(arg0):
    _wasm_store_delete = libiwasm.wasm_store_delete
    _wasm_store_delete.restype = None
    _wasm_store_delete.argtypes = [POINTER(wasm_store_t)]
    return _wasm_store_delete(arg0)

def wasm_store_new(arg0):
    _wasm_store_new = libiwasm.wasm_store_new
    _wasm_store_new.restype = POINTER(wasm_store_t)
    _wasm_store_new.argtypes = [POINTER(wasm_engine_t)]
    return _wasm_store_new(arg0)

wasm_mutability_t = c_uint8

WASM_CONST = 0
WASM_VAR = 1

class wasm_limits_t(Structure):
    _fields_ = [
        ("min", c_uint32),
        ("max", c_uint32),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_limits_t):
            return False
        return self.min == other.min and self.max == other.max

    def __repr__(self):
        return f"{{min={self.min}, max={self.max}}}"


class wasm_valtype_t(Structure):
    pass

def wasm_valtype_delete(arg0):
    _wasm_valtype_delete = libiwasm.wasm_valtype_delete
    _wasm_valtype_delete.restype = None
    _wasm_valtype_delete.argtypes = [POINTER(wasm_valtype_t)]
    return _wasm_valtype_delete(arg0)

class wasm_valtype_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_valtype_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_valtype_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_valtype_vec_new_empty(arg0):
    _wasm_valtype_vec_new_empty = libiwasm.wasm_valtype_vec_new_empty
    _wasm_valtype_vec_new_empty.restype = None
    _wasm_valtype_vec_new_empty.argtypes = [POINTER(wasm_valtype_vec_t)]
    return _wasm_valtype_vec_new_empty(arg0)

def wasm_valtype_vec_new_uninitialized(arg0,arg1):
    _wasm_valtype_vec_new_uninitialized = libiwasm.wasm_valtype_vec_new_uninitialized
    _wasm_valtype_vec_new_uninitialized.restype = None
    _wasm_valtype_vec_new_uninitialized.argtypes = [POINTER(wasm_valtype_vec_t),c_size_t]
    return _wasm_valtype_vec_new_uninitialized(arg0,arg1)

def wasm_valtype_vec_new(arg0,arg1,arg2):
    _wasm_valtype_vec_new = libiwasm.wasm_valtype_vec_new
    _wasm_valtype_vec_new.restype = None
    _wasm_valtype_vec_new.argtypes = [POINTER(wasm_valtype_vec_t),c_size_t,POINTER(POINTER(wasm_valtype_t))]
    return _wasm_valtype_vec_new(arg0,arg1,arg2)

def wasm_valtype_vec_copy(arg0,arg1):
    _wasm_valtype_vec_copy = libiwasm.wasm_valtype_vec_copy
    _wasm_valtype_vec_copy.restype = None
    _wasm_valtype_vec_copy.argtypes = [POINTER(wasm_valtype_vec_t),POINTER(wasm_valtype_vec_t)]
    return _wasm_valtype_vec_copy(arg0,arg1)

def wasm_valtype_vec_delete(arg0):
    _wasm_valtype_vec_delete = libiwasm.wasm_valtype_vec_delete
    _wasm_valtype_vec_delete.restype = None
    _wasm_valtype_vec_delete.argtypes = [POINTER(wasm_valtype_vec_t)]
    return _wasm_valtype_vec_delete(arg0)

def wasm_valtype_copy(arg0):
    _wasm_valtype_copy = libiwasm.wasm_valtype_copy
    _wasm_valtype_copy.restype = POINTER(wasm_valtype_t)
    _wasm_valtype_copy.argtypes = [POINTER(wasm_valtype_t)]
    return _wasm_valtype_copy(arg0)

wasm_valkind_t = c_uint8

WASM_I32 = 0
WASM_I64 = 1
WASM_F32 = 2
WASM_F64 = 3
WASM_ANYREF = 128
WASM_FUNCREF = 129

def wasm_valtype_new(arg0):
    _wasm_valtype_new = libiwasm.wasm_valtype_new
    _wasm_valtype_new.restype = POINTER(wasm_valtype_t)
    _wasm_valtype_new.argtypes = [wasm_valkind_t]
    return _wasm_valtype_new(arg0)

def wasm_valtype_kind(arg0):
    _wasm_valtype_kind = libiwasm.wasm_valtype_kind
    _wasm_valtype_kind.restype = wasm_valkind_t
    _wasm_valtype_kind.argtypes = [POINTER(wasm_valtype_t)]
    return _wasm_valtype_kind(arg0)

class wasm_functype_t(Structure):
    pass

def wasm_functype_delete(arg0):
    _wasm_functype_delete = libiwasm.wasm_functype_delete
    _wasm_functype_delete.restype = None
    _wasm_functype_delete.argtypes = [POINTER(wasm_functype_t)]
    return _wasm_functype_delete(arg0)

class wasm_functype_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_functype_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_functype_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_functype_vec_new_empty(arg0):
    _wasm_functype_vec_new_empty = libiwasm.wasm_functype_vec_new_empty
    _wasm_functype_vec_new_empty.restype = None
    _wasm_functype_vec_new_empty.argtypes = [POINTER(wasm_functype_vec_t)]
    return _wasm_functype_vec_new_empty(arg0)

def wasm_functype_vec_new_uninitialized(arg0,arg1):
    _wasm_functype_vec_new_uninitialized = libiwasm.wasm_functype_vec_new_uninitialized
    _wasm_functype_vec_new_uninitialized.restype = None
    _wasm_functype_vec_new_uninitialized.argtypes = [POINTER(wasm_functype_vec_t),c_size_t]
    return _wasm_functype_vec_new_uninitialized(arg0,arg1)

def wasm_functype_vec_new(arg0,arg1,arg2):
    _wasm_functype_vec_new = libiwasm.wasm_functype_vec_new
    _wasm_functype_vec_new.restype = None
    _wasm_functype_vec_new.argtypes = [POINTER(wasm_functype_vec_t),c_size_t,POINTER(POINTER(wasm_functype_t))]
    return _wasm_functype_vec_new(arg0,arg1,arg2)

def wasm_functype_vec_copy(arg0,arg1):
    _wasm_functype_vec_copy = libiwasm.wasm_functype_vec_copy
    _wasm_functype_vec_copy.restype = None
    _wasm_functype_vec_copy.argtypes = [POINTER(wasm_functype_vec_t),POINTER(wasm_functype_vec_t)]
    return _wasm_functype_vec_copy(arg0,arg1)

def wasm_functype_vec_delete(arg0):
    _wasm_functype_vec_delete = libiwasm.wasm_functype_vec_delete
    _wasm_functype_vec_delete.restype = None
    _wasm_functype_vec_delete.argtypes = [POINTER(wasm_functype_vec_t)]
    return _wasm_functype_vec_delete(arg0)

def wasm_functype_copy(arg0):
    _wasm_functype_copy = libiwasm.wasm_functype_copy
    _wasm_functype_copy.restype = POINTER(wasm_functype_t)
    _wasm_functype_copy.argtypes = [POINTER(wasm_functype_t)]
    return _wasm_functype_copy(arg0)

def wasm_functype_new(arg0,arg1):
    _wasm_functype_new = libiwasm.wasm_functype_new
    _wasm_functype_new.restype = POINTER(wasm_functype_t)
    _wasm_functype_new.argtypes = [POINTER(wasm_valtype_vec_t),POINTER(wasm_valtype_vec_t)]
    return _wasm_functype_new(arg0,arg1)

def wasm_functype_params(arg0):
    _wasm_functype_params = libiwasm.wasm_functype_params
    _wasm_functype_params.restype = POINTER(wasm_valtype_vec_t)
    _wasm_functype_params.argtypes = [POINTER(wasm_functype_t)]
    return _wasm_functype_params(arg0)

def wasm_functype_results(arg0):
    _wasm_functype_results = libiwasm.wasm_functype_results
    _wasm_functype_results.restype = POINTER(wasm_valtype_vec_t)
    _wasm_functype_results.argtypes = [POINTER(wasm_functype_t)]
    return _wasm_functype_results(arg0)

class wasm_globaltype_t(Structure):
    pass

def wasm_globaltype_delete(arg0):
    _wasm_globaltype_delete = libiwasm.wasm_globaltype_delete
    _wasm_globaltype_delete.restype = None
    _wasm_globaltype_delete.argtypes = [POINTER(wasm_globaltype_t)]
    return _wasm_globaltype_delete(arg0)

class wasm_globaltype_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_globaltype_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_globaltype_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_globaltype_vec_new_empty(arg0):
    _wasm_globaltype_vec_new_empty = libiwasm.wasm_globaltype_vec_new_empty
    _wasm_globaltype_vec_new_empty.restype = None
    _wasm_globaltype_vec_new_empty.argtypes = [POINTER(wasm_globaltype_vec_t)]
    return _wasm_globaltype_vec_new_empty(arg0)

def wasm_globaltype_vec_new_uninitialized(arg0,arg1):
    _wasm_globaltype_vec_new_uninitialized = libiwasm.wasm_globaltype_vec_new_uninitialized
    _wasm_globaltype_vec_new_uninitialized.restype = None
    _wasm_globaltype_vec_new_uninitialized.argtypes = [POINTER(wasm_globaltype_vec_t),c_size_t]
    return _wasm_globaltype_vec_new_uninitialized(arg0,arg1)

def wasm_globaltype_vec_new(arg0,arg1,arg2):
    _wasm_globaltype_vec_new = libiwasm.wasm_globaltype_vec_new
    _wasm_globaltype_vec_new.restype = None
    _wasm_globaltype_vec_new.argtypes = [POINTER(wasm_globaltype_vec_t),c_size_t,POINTER(POINTER(wasm_globaltype_t))]
    return _wasm_globaltype_vec_new(arg0,arg1,arg2)

def wasm_globaltype_vec_copy(arg0,arg1):
    _wasm_globaltype_vec_copy = libiwasm.wasm_globaltype_vec_copy
    _wasm_globaltype_vec_copy.restype = None
    _wasm_globaltype_vec_copy.argtypes = [POINTER(wasm_globaltype_vec_t),POINTER(wasm_globaltype_vec_t)]
    return _wasm_globaltype_vec_copy(arg0,arg1)

def wasm_globaltype_vec_delete(arg0):
    _wasm_globaltype_vec_delete = libiwasm.wasm_globaltype_vec_delete
    _wasm_globaltype_vec_delete.restype = None
    _wasm_globaltype_vec_delete.argtypes = [POINTER(wasm_globaltype_vec_t)]
    return _wasm_globaltype_vec_delete(arg0)

def wasm_globaltype_copy(arg0):
    _wasm_globaltype_copy = libiwasm.wasm_globaltype_copy
    _wasm_globaltype_copy.restype = POINTER(wasm_globaltype_t)
    _wasm_globaltype_copy.argtypes = [POINTER(wasm_globaltype_t)]
    return _wasm_globaltype_copy(arg0)

def wasm_globaltype_new(arg0,arg1):
    _wasm_globaltype_new = libiwasm.wasm_globaltype_new
    _wasm_globaltype_new.restype = POINTER(wasm_globaltype_t)
    _wasm_globaltype_new.argtypes = [POINTER(wasm_valtype_t),wasm_mutability_t]
    return _wasm_globaltype_new(arg0,arg1)

def wasm_globaltype_content(arg0):
    _wasm_globaltype_content = libiwasm.wasm_globaltype_content
    _wasm_globaltype_content.restype = POINTER(wasm_valtype_t)
    _wasm_globaltype_content.argtypes = [POINTER(wasm_globaltype_t)]
    return _wasm_globaltype_content(arg0)

def wasm_globaltype_mutability(arg0):
    _wasm_globaltype_mutability = libiwasm.wasm_globaltype_mutability
    _wasm_globaltype_mutability.restype = wasm_mutability_t
    _wasm_globaltype_mutability.argtypes = [POINTER(wasm_globaltype_t)]
    return _wasm_globaltype_mutability(arg0)

class wasm_tabletype_t(Structure):
    pass

def wasm_tabletype_delete(arg0):
    _wasm_tabletype_delete = libiwasm.wasm_tabletype_delete
    _wasm_tabletype_delete.restype = None
    _wasm_tabletype_delete.argtypes = [POINTER(wasm_tabletype_t)]
    return _wasm_tabletype_delete(arg0)

class wasm_tabletype_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_tabletype_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_tabletype_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_tabletype_vec_new_empty(arg0):
    _wasm_tabletype_vec_new_empty = libiwasm.wasm_tabletype_vec_new_empty
    _wasm_tabletype_vec_new_empty.restype = None
    _wasm_tabletype_vec_new_empty.argtypes = [POINTER(wasm_tabletype_vec_t)]
    return _wasm_tabletype_vec_new_empty(arg0)

def wasm_tabletype_vec_new_uninitialized(arg0,arg1):
    _wasm_tabletype_vec_new_uninitialized = libiwasm.wasm_tabletype_vec_new_uninitialized
    _wasm_tabletype_vec_new_uninitialized.restype = None
    _wasm_tabletype_vec_new_uninitialized.argtypes = [POINTER(wasm_tabletype_vec_t),c_size_t]
    return _wasm_tabletype_vec_new_uninitialized(arg0,arg1)

def wasm_tabletype_vec_new(arg0,arg1,arg2):
    _wasm_tabletype_vec_new = libiwasm.wasm_tabletype_vec_new
    _wasm_tabletype_vec_new.restype = None
    _wasm_tabletype_vec_new.argtypes = [POINTER(wasm_tabletype_vec_t),c_size_t,POINTER(POINTER(wasm_tabletype_t))]
    return _wasm_tabletype_vec_new(arg0,arg1,arg2)

def wasm_tabletype_vec_copy(arg0,arg1):
    _wasm_tabletype_vec_copy = libiwasm.wasm_tabletype_vec_copy
    _wasm_tabletype_vec_copy.restype = None
    _wasm_tabletype_vec_copy.argtypes = [POINTER(wasm_tabletype_vec_t),POINTER(wasm_tabletype_vec_t)]
    return _wasm_tabletype_vec_copy(arg0,arg1)

def wasm_tabletype_vec_delete(arg0):
    _wasm_tabletype_vec_delete = libiwasm.wasm_tabletype_vec_delete
    _wasm_tabletype_vec_delete.restype = None
    _wasm_tabletype_vec_delete.argtypes = [POINTER(wasm_tabletype_vec_t)]
    return _wasm_tabletype_vec_delete(arg0)

def wasm_tabletype_copy(arg0):
    _wasm_tabletype_copy = libiwasm.wasm_tabletype_copy
    _wasm_tabletype_copy.restype = POINTER(wasm_tabletype_t)
    _wasm_tabletype_copy.argtypes = [POINTER(wasm_tabletype_t)]
    return _wasm_tabletype_copy(arg0)

def wasm_tabletype_new(arg0,arg1):
    _wasm_tabletype_new = libiwasm.wasm_tabletype_new
    _wasm_tabletype_new.restype = POINTER(wasm_tabletype_t)
    _wasm_tabletype_new.argtypes = [POINTER(wasm_valtype_t),POINTER(wasm_limits_t)]
    return _wasm_tabletype_new(arg0,arg1)

def wasm_tabletype_element(arg0):
    _wasm_tabletype_element = libiwasm.wasm_tabletype_element
    _wasm_tabletype_element.restype = POINTER(wasm_valtype_t)
    _wasm_tabletype_element.argtypes = [POINTER(wasm_tabletype_t)]
    return _wasm_tabletype_element(arg0)

def wasm_tabletype_limits(arg0):
    _wasm_tabletype_limits = libiwasm.wasm_tabletype_limits
    _wasm_tabletype_limits.restype = POINTER(wasm_limits_t)
    _wasm_tabletype_limits.argtypes = [POINTER(wasm_tabletype_t)]
    return _wasm_tabletype_limits(arg0)

class wasm_memorytype_t(Structure):
    pass

def wasm_memorytype_delete(arg0):
    _wasm_memorytype_delete = libiwasm.wasm_memorytype_delete
    _wasm_memorytype_delete.restype = None
    _wasm_memorytype_delete.argtypes = [POINTER(wasm_memorytype_t)]
    return _wasm_memorytype_delete(arg0)

class wasm_memorytype_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_memorytype_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_memorytype_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_memorytype_vec_new_empty(arg0):
    _wasm_memorytype_vec_new_empty = libiwasm.wasm_memorytype_vec_new_empty
    _wasm_memorytype_vec_new_empty.restype = None
    _wasm_memorytype_vec_new_empty.argtypes = [POINTER(wasm_memorytype_vec_t)]
    return _wasm_memorytype_vec_new_empty(arg0)

def wasm_memorytype_vec_new_uninitialized(arg0,arg1):
    _wasm_memorytype_vec_new_uninitialized = libiwasm.wasm_memorytype_vec_new_uninitialized
    _wasm_memorytype_vec_new_uninitialized.restype = None
    _wasm_memorytype_vec_new_uninitialized.argtypes = [POINTER(wasm_memorytype_vec_t),c_size_t]
    return _wasm_memorytype_vec_new_uninitialized(arg0,arg1)

def wasm_memorytype_vec_new(arg0,arg1,arg2):
    _wasm_memorytype_vec_new = libiwasm.wasm_memorytype_vec_new
    _wasm_memorytype_vec_new.restype = None
    _wasm_memorytype_vec_new.argtypes = [POINTER(wasm_memorytype_vec_t),c_size_t,POINTER(POINTER(wasm_memorytype_t))]
    return _wasm_memorytype_vec_new(arg0,arg1,arg2)

def wasm_memorytype_vec_copy(arg0,arg1):
    _wasm_memorytype_vec_copy = libiwasm.wasm_memorytype_vec_copy
    _wasm_memorytype_vec_copy.restype = None
    _wasm_memorytype_vec_copy.argtypes = [POINTER(wasm_memorytype_vec_t),POINTER(wasm_memorytype_vec_t)]
    return _wasm_memorytype_vec_copy(arg0,arg1)

def wasm_memorytype_vec_delete(arg0):
    _wasm_memorytype_vec_delete = libiwasm.wasm_memorytype_vec_delete
    _wasm_memorytype_vec_delete.restype = None
    _wasm_memorytype_vec_delete.argtypes = [POINTER(wasm_memorytype_vec_t)]
    return _wasm_memorytype_vec_delete(arg0)

def wasm_memorytype_copy(arg0):
    _wasm_memorytype_copy = libiwasm.wasm_memorytype_copy
    _wasm_memorytype_copy.restype = POINTER(wasm_memorytype_t)
    _wasm_memorytype_copy.argtypes = [POINTER(wasm_memorytype_t)]
    return _wasm_memorytype_copy(arg0)

def wasm_memorytype_new(arg0):
    _wasm_memorytype_new = libiwasm.wasm_memorytype_new
    _wasm_memorytype_new.restype = POINTER(wasm_memorytype_t)
    _wasm_memorytype_new.argtypes = [POINTER(wasm_limits_t)]
    return _wasm_memorytype_new(arg0)

def wasm_memorytype_limits(arg0):
    _wasm_memorytype_limits = libiwasm.wasm_memorytype_limits
    _wasm_memorytype_limits.restype = POINTER(wasm_limits_t)
    _wasm_memorytype_limits.argtypes = [POINTER(wasm_memorytype_t)]
    return _wasm_memorytype_limits(arg0)

class wasm_externtype_t(Structure):
    pass

def wasm_externtype_delete(arg0):
    _wasm_externtype_delete = libiwasm.wasm_externtype_delete
    _wasm_externtype_delete.restype = None
    _wasm_externtype_delete.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_delete(arg0)

class wasm_externtype_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_externtype_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_externtype_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_externtype_vec_new_empty(arg0):
    _wasm_externtype_vec_new_empty = libiwasm.wasm_externtype_vec_new_empty
    _wasm_externtype_vec_new_empty.restype = None
    _wasm_externtype_vec_new_empty.argtypes = [POINTER(wasm_externtype_vec_t)]
    return _wasm_externtype_vec_new_empty(arg0)

def wasm_externtype_vec_new_uninitialized(arg0,arg1):
    _wasm_externtype_vec_new_uninitialized = libiwasm.wasm_externtype_vec_new_uninitialized
    _wasm_externtype_vec_new_uninitialized.restype = None
    _wasm_externtype_vec_new_uninitialized.argtypes = [POINTER(wasm_externtype_vec_t),c_size_t]
    return _wasm_externtype_vec_new_uninitialized(arg0,arg1)

def wasm_externtype_vec_new(arg0,arg1,arg2):
    _wasm_externtype_vec_new = libiwasm.wasm_externtype_vec_new
    _wasm_externtype_vec_new.restype = None
    _wasm_externtype_vec_new.argtypes = [POINTER(wasm_externtype_vec_t),c_size_t,POINTER(POINTER(wasm_externtype_t))]
    return _wasm_externtype_vec_new(arg0,arg1,arg2)

def wasm_externtype_vec_copy(arg0,arg1):
    _wasm_externtype_vec_copy = libiwasm.wasm_externtype_vec_copy
    _wasm_externtype_vec_copy.restype = None
    _wasm_externtype_vec_copy.argtypes = [POINTER(wasm_externtype_vec_t),POINTER(wasm_externtype_vec_t)]
    return _wasm_externtype_vec_copy(arg0,arg1)

def wasm_externtype_vec_delete(arg0):
    _wasm_externtype_vec_delete = libiwasm.wasm_externtype_vec_delete
    _wasm_externtype_vec_delete.restype = None
    _wasm_externtype_vec_delete.argtypes = [POINTER(wasm_externtype_vec_t)]
    return _wasm_externtype_vec_delete(arg0)

def wasm_externtype_copy(arg0):
    _wasm_externtype_copy = libiwasm.wasm_externtype_copy
    _wasm_externtype_copy.restype = POINTER(wasm_externtype_t)
    _wasm_externtype_copy.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_copy(arg0)

wasm_externkind_t = c_uint8

WASM_EXTERN_FUNC = 0
WASM_EXTERN_GLOBAL = 1
WASM_EXTERN_TABLE = 2
WASM_EXTERN_MEMORY = 3

def wasm_externtype_kind(arg0):
    _wasm_externtype_kind = libiwasm.wasm_externtype_kind
    _wasm_externtype_kind.restype = wasm_externkind_t
    _wasm_externtype_kind.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_kind(arg0)

def wasm_functype_as_externtype(arg0):
    _wasm_functype_as_externtype = libiwasm.wasm_functype_as_externtype
    _wasm_functype_as_externtype.restype = POINTER(wasm_externtype_t)
    _wasm_functype_as_externtype.argtypes = [POINTER(wasm_functype_t)]
    return _wasm_functype_as_externtype(arg0)

def wasm_globaltype_as_externtype(arg0):
    _wasm_globaltype_as_externtype = libiwasm.wasm_globaltype_as_externtype
    _wasm_globaltype_as_externtype.restype = POINTER(wasm_externtype_t)
    _wasm_globaltype_as_externtype.argtypes = [POINTER(wasm_globaltype_t)]
    return _wasm_globaltype_as_externtype(arg0)

def wasm_tabletype_as_externtype(arg0):
    _wasm_tabletype_as_externtype = libiwasm.wasm_tabletype_as_externtype
    _wasm_tabletype_as_externtype.restype = POINTER(wasm_externtype_t)
    _wasm_tabletype_as_externtype.argtypes = [POINTER(wasm_tabletype_t)]
    return _wasm_tabletype_as_externtype(arg0)

def wasm_memorytype_as_externtype(arg0):
    _wasm_memorytype_as_externtype = libiwasm.wasm_memorytype_as_externtype
    _wasm_memorytype_as_externtype.restype = POINTER(wasm_externtype_t)
    _wasm_memorytype_as_externtype.argtypes = [POINTER(wasm_memorytype_t)]
    return _wasm_memorytype_as_externtype(arg0)

def wasm_externtype_as_functype(arg0):
    _wasm_externtype_as_functype = libiwasm.wasm_externtype_as_functype
    _wasm_externtype_as_functype.restype = POINTER(wasm_functype_t)
    _wasm_externtype_as_functype.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_as_functype(arg0)

def wasm_externtype_as_globaltype(arg0):
    _wasm_externtype_as_globaltype = libiwasm.wasm_externtype_as_globaltype
    _wasm_externtype_as_globaltype.restype = POINTER(wasm_globaltype_t)
    _wasm_externtype_as_globaltype.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_as_globaltype(arg0)

def wasm_externtype_as_tabletype(arg0):
    _wasm_externtype_as_tabletype = libiwasm.wasm_externtype_as_tabletype
    _wasm_externtype_as_tabletype.restype = POINTER(wasm_tabletype_t)
    _wasm_externtype_as_tabletype.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_as_tabletype(arg0)

def wasm_externtype_as_memorytype(arg0):
    _wasm_externtype_as_memorytype = libiwasm.wasm_externtype_as_memorytype
    _wasm_externtype_as_memorytype.restype = POINTER(wasm_memorytype_t)
    _wasm_externtype_as_memorytype.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_as_memorytype(arg0)

def wasm_functype_as_externtype_const(arg0):
    _wasm_functype_as_externtype_const = libiwasm.wasm_functype_as_externtype_const
    _wasm_functype_as_externtype_const.restype = POINTER(wasm_externtype_t)
    _wasm_functype_as_externtype_const.argtypes = [POINTER(wasm_functype_t)]
    return _wasm_functype_as_externtype_const(arg0)

def wasm_globaltype_as_externtype_const(arg0):
    _wasm_globaltype_as_externtype_const = libiwasm.wasm_globaltype_as_externtype_const
    _wasm_globaltype_as_externtype_const.restype = POINTER(wasm_externtype_t)
    _wasm_globaltype_as_externtype_const.argtypes = [POINTER(wasm_globaltype_t)]
    return _wasm_globaltype_as_externtype_const(arg0)

def wasm_tabletype_as_externtype_const(arg0):
    _wasm_tabletype_as_externtype_const = libiwasm.wasm_tabletype_as_externtype_const
    _wasm_tabletype_as_externtype_const.restype = POINTER(wasm_externtype_t)
    _wasm_tabletype_as_externtype_const.argtypes = [POINTER(wasm_tabletype_t)]
    return _wasm_tabletype_as_externtype_const(arg0)

def wasm_memorytype_as_externtype_const(arg0):
    _wasm_memorytype_as_externtype_const = libiwasm.wasm_memorytype_as_externtype_const
    _wasm_memorytype_as_externtype_const.restype = POINTER(wasm_externtype_t)
    _wasm_memorytype_as_externtype_const.argtypes = [POINTER(wasm_memorytype_t)]
    return _wasm_memorytype_as_externtype_const(arg0)

def wasm_externtype_as_functype_const(arg0):
    _wasm_externtype_as_functype_const = libiwasm.wasm_externtype_as_functype_const
    _wasm_externtype_as_functype_const.restype = POINTER(wasm_functype_t)
    _wasm_externtype_as_functype_const.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_as_functype_const(arg0)

def wasm_externtype_as_globaltype_const(arg0):
    _wasm_externtype_as_globaltype_const = libiwasm.wasm_externtype_as_globaltype_const
    _wasm_externtype_as_globaltype_const.restype = POINTER(wasm_globaltype_t)
    _wasm_externtype_as_globaltype_const.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_as_globaltype_const(arg0)

def wasm_externtype_as_tabletype_const(arg0):
    _wasm_externtype_as_tabletype_const = libiwasm.wasm_externtype_as_tabletype_const
    _wasm_externtype_as_tabletype_const.restype = POINTER(wasm_tabletype_t)
    _wasm_externtype_as_tabletype_const.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_as_tabletype_const(arg0)

def wasm_externtype_as_memorytype_const(arg0):
    _wasm_externtype_as_memorytype_const = libiwasm.wasm_externtype_as_memorytype_const
    _wasm_externtype_as_memorytype_const.restype = POINTER(wasm_memorytype_t)
    _wasm_externtype_as_memorytype_const.argtypes = [POINTER(wasm_externtype_t)]
    return _wasm_externtype_as_memorytype_const(arg0)

class wasm_importtype_t(Structure):
    pass

def wasm_importtype_delete(arg0):
    _wasm_importtype_delete = libiwasm.wasm_importtype_delete
    _wasm_importtype_delete.restype = None
    _wasm_importtype_delete.argtypes = [POINTER(wasm_importtype_t)]
    return _wasm_importtype_delete(arg0)

class wasm_importtype_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_importtype_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_importtype_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_importtype_vec_new_empty(arg0):
    _wasm_importtype_vec_new_empty = libiwasm.wasm_importtype_vec_new_empty
    _wasm_importtype_vec_new_empty.restype = None
    _wasm_importtype_vec_new_empty.argtypes = [POINTER(wasm_importtype_vec_t)]
    return _wasm_importtype_vec_new_empty(arg0)

def wasm_importtype_vec_new_uninitialized(arg0,arg1):
    _wasm_importtype_vec_new_uninitialized = libiwasm.wasm_importtype_vec_new_uninitialized
    _wasm_importtype_vec_new_uninitialized.restype = None
    _wasm_importtype_vec_new_uninitialized.argtypes = [POINTER(wasm_importtype_vec_t),c_size_t]
    return _wasm_importtype_vec_new_uninitialized(arg0,arg1)

def wasm_importtype_vec_new(arg0,arg1,arg2):
    _wasm_importtype_vec_new = libiwasm.wasm_importtype_vec_new
    _wasm_importtype_vec_new.restype = None
    _wasm_importtype_vec_new.argtypes = [POINTER(wasm_importtype_vec_t),c_size_t,POINTER(POINTER(wasm_importtype_t))]
    return _wasm_importtype_vec_new(arg0,arg1,arg2)

def wasm_importtype_vec_copy(arg0,arg1):
    _wasm_importtype_vec_copy = libiwasm.wasm_importtype_vec_copy
    _wasm_importtype_vec_copy.restype = None
    _wasm_importtype_vec_copy.argtypes = [POINTER(wasm_importtype_vec_t),POINTER(wasm_importtype_vec_t)]
    return _wasm_importtype_vec_copy(arg0,arg1)

def wasm_importtype_vec_delete(arg0):
    _wasm_importtype_vec_delete = libiwasm.wasm_importtype_vec_delete
    _wasm_importtype_vec_delete.restype = None
    _wasm_importtype_vec_delete.argtypes = [POINTER(wasm_importtype_vec_t)]
    return _wasm_importtype_vec_delete(arg0)

def wasm_importtype_copy(arg0):
    _wasm_importtype_copy = libiwasm.wasm_importtype_copy
    _wasm_importtype_copy.restype = POINTER(wasm_importtype_t)
    _wasm_importtype_copy.argtypes = [POINTER(wasm_importtype_t)]
    return _wasm_importtype_copy(arg0)

def wasm_importtype_new(arg0,arg1,arg2):
    _wasm_importtype_new = libiwasm.wasm_importtype_new
    _wasm_importtype_new.restype = POINTER(wasm_importtype_t)
    _wasm_importtype_new.argtypes = [POINTER(wasm_name_t),POINTER(wasm_name_t),POINTER(wasm_externtype_t)]
    return _wasm_importtype_new(arg0,arg1,arg2)

def wasm_importtype_module(arg0):
    _wasm_importtype_module = libiwasm.wasm_importtype_module
    _wasm_importtype_module.restype = POINTER(wasm_name_t)
    _wasm_importtype_module.argtypes = [POINTER(wasm_importtype_t)]
    return _wasm_importtype_module(arg0)

def wasm_importtype_name(arg0):
    _wasm_importtype_name = libiwasm.wasm_importtype_name
    _wasm_importtype_name.restype = POINTER(wasm_name_t)
    _wasm_importtype_name.argtypes = [POINTER(wasm_importtype_t)]
    return _wasm_importtype_name(arg0)

def wasm_importtype_type(arg0):
    _wasm_importtype_type = libiwasm.wasm_importtype_type
    _wasm_importtype_type.restype = POINTER(wasm_externtype_t)
    _wasm_importtype_type.argtypes = [POINTER(wasm_importtype_t)]
    return _wasm_importtype_type(arg0)

class wasm_exporttype_t(Structure):
    pass

def wasm_exporttype_delete(arg0):
    _wasm_exporttype_delete = libiwasm.wasm_exporttype_delete
    _wasm_exporttype_delete.restype = None
    _wasm_exporttype_delete.argtypes = [POINTER(wasm_exporttype_t)]
    return _wasm_exporttype_delete(arg0)

class wasm_exporttype_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_exporttype_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_exporttype_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_exporttype_vec_new_empty(arg0):
    _wasm_exporttype_vec_new_empty = libiwasm.wasm_exporttype_vec_new_empty
    _wasm_exporttype_vec_new_empty.restype = None
    _wasm_exporttype_vec_new_empty.argtypes = [POINTER(wasm_exporttype_vec_t)]
    return _wasm_exporttype_vec_new_empty(arg0)

def wasm_exporttype_vec_new_uninitialized(arg0,arg1):
    _wasm_exporttype_vec_new_uninitialized = libiwasm.wasm_exporttype_vec_new_uninitialized
    _wasm_exporttype_vec_new_uninitialized.restype = None
    _wasm_exporttype_vec_new_uninitialized.argtypes = [POINTER(wasm_exporttype_vec_t),c_size_t]
    return _wasm_exporttype_vec_new_uninitialized(arg0,arg1)

def wasm_exporttype_vec_new(arg0,arg1,arg2):
    _wasm_exporttype_vec_new = libiwasm.wasm_exporttype_vec_new
    _wasm_exporttype_vec_new.restype = None
    _wasm_exporttype_vec_new.argtypes = [POINTER(wasm_exporttype_vec_t),c_size_t,POINTER(POINTER(wasm_exporttype_t))]
    return _wasm_exporttype_vec_new(arg0,arg1,arg2)

def wasm_exporttype_vec_copy(arg0,arg1):
    _wasm_exporttype_vec_copy = libiwasm.wasm_exporttype_vec_copy
    _wasm_exporttype_vec_copy.restype = None
    _wasm_exporttype_vec_copy.argtypes = [POINTER(wasm_exporttype_vec_t),POINTER(wasm_exporttype_vec_t)]
    return _wasm_exporttype_vec_copy(arg0,arg1)

def wasm_exporttype_vec_delete(arg0):
    _wasm_exporttype_vec_delete = libiwasm.wasm_exporttype_vec_delete
    _wasm_exporttype_vec_delete.restype = None
    _wasm_exporttype_vec_delete.argtypes = [POINTER(wasm_exporttype_vec_t)]
    return _wasm_exporttype_vec_delete(arg0)

def wasm_exporttype_copy(arg0):
    _wasm_exporttype_copy = libiwasm.wasm_exporttype_copy
    _wasm_exporttype_copy.restype = POINTER(wasm_exporttype_t)
    _wasm_exporttype_copy.argtypes = [POINTER(wasm_exporttype_t)]
    return _wasm_exporttype_copy(arg0)

def wasm_exporttype_new(arg0,arg1):
    _wasm_exporttype_new = libiwasm.wasm_exporttype_new
    _wasm_exporttype_new.restype = POINTER(wasm_exporttype_t)
    _wasm_exporttype_new.argtypes = [POINTER(wasm_name_t),POINTER(wasm_externtype_t)]
    return _wasm_exporttype_new(arg0,arg1)

def wasm_exporttype_name(arg0):
    _wasm_exporttype_name = libiwasm.wasm_exporttype_name
    _wasm_exporttype_name.restype = POINTER(wasm_name_t)
    _wasm_exporttype_name.argtypes = [POINTER(wasm_exporttype_t)]
    return _wasm_exporttype_name(arg0)

def wasm_exporttype_type(arg0):
    _wasm_exporttype_type = libiwasm.wasm_exporttype_type
    _wasm_exporttype_type.restype = POINTER(wasm_externtype_t)
    _wasm_exporttype_type.argtypes = [POINTER(wasm_exporttype_t)]
    return _wasm_exporttype_type(arg0)

def wasm_val_delete(arg0):
    _wasm_val_delete = libiwasm.wasm_val_delete
    _wasm_val_delete.restype = None
    _wasm_val_delete.argtypes = [POINTER(wasm_val_t)]
    return _wasm_val_delete(arg0)

def wasm_val_copy(arg0,arg1):
    _wasm_val_copy = libiwasm.wasm_val_copy
    _wasm_val_copy.restype = None
    _wasm_val_copy.argtypes = [POINTER(wasm_val_t),POINTER(wasm_val_t)]
    return _wasm_val_copy(arg0,arg1)

class wasm_val_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(wasm_val_t)),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_val_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(self.data[i])
                ret += " "
        return ret



def wasm_val_vec_new_empty(arg0):
    _wasm_val_vec_new_empty = libiwasm.wasm_val_vec_new_empty
    _wasm_val_vec_new_empty.restype = None
    _wasm_val_vec_new_empty.argtypes = [POINTER(wasm_val_vec_t)]
    return _wasm_val_vec_new_empty(arg0)

def wasm_val_vec_new_uninitialized(arg0,arg1):
    _wasm_val_vec_new_uninitialized = libiwasm.wasm_val_vec_new_uninitialized
    _wasm_val_vec_new_uninitialized.restype = None
    _wasm_val_vec_new_uninitialized.argtypes = [POINTER(wasm_val_vec_t),c_size_t]
    return _wasm_val_vec_new_uninitialized(arg0,arg1)

def wasm_val_vec_new(arg0,arg1,arg2):
    _wasm_val_vec_new = libiwasm.wasm_val_vec_new
    _wasm_val_vec_new.restype = None
    _wasm_val_vec_new.argtypes = [POINTER(wasm_val_vec_t),c_size_t,POINTER(wasm_val_t)]
    return _wasm_val_vec_new(arg0,arg1,arg2)

def wasm_val_vec_copy(arg0,arg1):
    _wasm_val_vec_copy = libiwasm.wasm_val_vec_copy
    _wasm_val_vec_copy.restype = None
    _wasm_val_vec_copy.argtypes = [POINTER(wasm_val_vec_t),POINTER(wasm_val_vec_t)]
    return _wasm_val_vec_copy(arg0,arg1)

def wasm_val_vec_delete(arg0):
    _wasm_val_vec_delete = libiwasm.wasm_val_vec_delete
    _wasm_val_vec_delete.restype = None
    _wasm_val_vec_delete.argtypes = [POINTER(wasm_val_vec_t)]
    return _wasm_val_vec_delete(arg0)

def wasm_ref_delete(arg0):
    _wasm_ref_delete = libiwasm.wasm_ref_delete
    _wasm_ref_delete.restype = None
    _wasm_ref_delete.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_delete(arg0)

def wasm_ref_copy(arg0):
    _wasm_ref_copy = libiwasm.wasm_ref_copy
    _wasm_ref_copy.restype = POINTER(wasm_ref_t)
    _wasm_ref_copy.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_copy(arg0)

def wasm_ref_same(arg0,arg1):
    _wasm_ref_same = libiwasm.wasm_ref_same
    _wasm_ref_same.restype = c_bool
    _wasm_ref_same.argtypes = [POINTER(wasm_ref_t),POINTER(wasm_ref_t)]
    return _wasm_ref_same(arg0,arg1)

def wasm_ref_get_host_info(arg0):
    _wasm_ref_get_host_info = libiwasm.wasm_ref_get_host_info
    _wasm_ref_get_host_info.restype = c_void_p
    _wasm_ref_get_host_info.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_get_host_info(arg0)

def wasm_ref_set_host_info(arg0,arg1):
    _wasm_ref_set_host_info = libiwasm.wasm_ref_set_host_info
    _wasm_ref_set_host_info.restype = None
    _wasm_ref_set_host_info.argtypes = [POINTER(wasm_ref_t),c_void_p]
    return _wasm_ref_set_host_info(arg0,arg1)

def wasm_ref_set_host_info_with_finalizer(arg0,arg1,arg2):
    _wasm_ref_set_host_info_with_finalizer = libiwasm.wasm_ref_set_host_info_with_finalizer
    _wasm_ref_set_host_info_with_finalizer.restype = None
    _wasm_ref_set_host_info_with_finalizer.argtypes = [POINTER(wasm_ref_t),c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_ref_set_host_info_with_finalizer(arg0,arg1,arg2)

class wasm_frame_t(Structure):
    pass

def wasm_frame_delete(arg0):
    _wasm_frame_delete = libiwasm.wasm_frame_delete
    _wasm_frame_delete.restype = None
    _wasm_frame_delete.argtypes = [POINTER(wasm_frame_t)]
    return _wasm_frame_delete(arg0)

class wasm_frame_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_frame_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_frame_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_frame_vec_new_empty(arg0):
    _wasm_frame_vec_new_empty = libiwasm.wasm_frame_vec_new_empty
    _wasm_frame_vec_new_empty.restype = None
    _wasm_frame_vec_new_empty.argtypes = [POINTER(wasm_frame_vec_t)]
    return _wasm_frame_vec_new_empty(arg0)

def wasm_frame_vec_new_uninitialized(arg0,arg1):
    _wasm_frame_vec_new_uninitialized = libiwasm.wasm_frame_vec_new_uninitialized
    _wasm_frame_vec_new_uninitialized.restype = None
    _wasm_frame_vec_new_uninitialized.argtypes = [POINTER(wasm_frame_vec_t),c_size_t]
    return _wasm_frame_vec_new_uninitialized(arg0,arg1)

def wasm_frame_vec_new(arg0,arg1,arg2):
    _wasm_frame_vec_new = libiwasm.wasm_frame_vec_new
    _wasm_frame_vec_new.restype = None
    _wasm_frame_vec_new.argtypes = [POINTER(wasm_frame_vec_t),c_size_t,POINTER(POINTER(wasm_frame_t))]
    return _wasm_frame_vec_new(arg0,arg1,arg2)

def wasm_frame_vec_copy(arg0,arg1):
    _wasm_frame_vec_copy = libiwasm.wasm_frame_vec_copy
    _wasm_frame_vec_copy.restype = None
    _wasm_frame_vec_copy.argtypes = [POINTER(wasm_frame_vec_t),POINTER(wasm_frame_vec_t)]
    return _wasm_frame_vec_copy(arg0,arg1)

def wasm_frame_vec_delete(arg0):
    _wasm_frame_vec_delete = libiwasm.wasm_frame_vec_delete
    _wasm_frame_vec_delete.restype = None
    _wasm_frame_vec_delete.argtypes = [POINTER(wasm_frame_vec_t)]
    return _wasm_frame_vec_delete(arg0)

def wasm_frame_copy(arg0):
    _wasm_frame_copy = libiwasm.wasm_frame_copy
    _wasm_frame_copy.restype = POINTER(wasm_frame_t)
    _wasm_frame_copy.argtypes = [POINTER(wasm_frame_t)]
    return _wasm_frame_copy(arg0)

def wasm_frame_instance(arg0):
    _wasm_frame_instance = libiwasm.wasm_frame_instance
    _wasm_frame_instance.restype = POINTER(wasm_instance_t)
    _wasm_frame_instance.argtypes = [POINTER(wasm_frame_t)]
    return _wasm_frame_instance(arg0)

def wasm_frame_func_index(arg0):
    _wasm_frame_func_index = libiwasm.wasm_frame_func_index
    _wasm_frame_func_index.restype = c_uint32
    _wasm_frame_func_index.argtypes = [POINTER(wasm_frame_t)]
    return _wasm_frame_func_index(arg0)

def wasm_frame_func_offset(arg0):
    _wasm_frame_func_offset = libiwasm.wasm_frame_func_offset
    _wasm_frame_func_offset.restype = c_size_t
    _wasm_frame_func_offset.argtypes = [POINTER(wasm_frame_t)]
    return _wasm_frame_func_offset(arg0)

def wasm_frame_module_offset(arg0):
    _wasm_frame_module_offset = libiwasm.wasm_frame_module_offset
    _wasm_frame_module_offset.restype = c_size_t
    _wasm_frame_module_offset.argtypes = [POINTER(wasm_frame_t)]
    return _wasm_frame_module_offset(arg0)

wasm_message_t = wasm_name_t

class wasm_trap_t(Structure):
    pass

def wasm_trap_delete(arg0):
    _wasm_trap_delete = libiwasm.wasm_trap_delete
    _wasm_trap_delete.restype = None
    _wasm_trap_delete.argtypes = [POINTER(wasm_trap_t)]
    return _wasm_trap_delete(arg0)

def wasm_trap_copy(arg0):
    _wasm_trap_copy = libiwasm.wasm_trap_copy
    _wasm_trap_copy.restype = POINTER(wasm_trap_t)
    _wasm_trap_copy.argtypes = [POINTER(wasm_trap_t)]
    return _wasm_trap_copy(arg0)

def wasm_trap_same(arg0,arg1):
    _wasm_trap_same = libiwasm.wasm_trap_same
    _wasm_trap_same.restype = c_bool
    _wasm_trap_same.argtypes = [POINTER(wasm_trap_t),POINTER(wasm_trap_t)]
    return _wasm_trap_same(arg0,arg1)

def wasm_trap_get_host_info(arg0):
    _wasm_trap_get_host_info = libiwasm.wasm_trap_get_host_info
    _wasm_trap_get_host_info.restype = c_void_p
    _wasm_trap_get_host_info.argtypes = [POINTER(wasm_trap_t)]
    return _wasm_trap_get_host_info(arg0)

def wasm_trap_set_host_info(arg0,arg1):
    _wasm_trap_set_host_info = libiwasm.wasm_trap_set_host_info
    _wasm_trap_set_host_info.restype = None
    _wasm_trap_set_host_info.argtypes = [POINTER(wasm_trap_t),c_void_p]
    return _wasm_trap_set_host_info(arg0,arg1)

def wasm_trap_set_host_info_with_finalizer(arg0,arg1,arg2):
    _wasm_trap_set_host_info_with_finalizer = libiwasm.wasm_trap_set_host_info_with_finalizer
    _wasm_trap_set_host_info_with_finalizer.restype = None
    _wasm_trap_set_host_info_with_finalizer.argtypes = [POINTER(wasm_trap_t),c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_trap_set_host_info_with_finalizer(arg0,arg1,arg2)

def wasm_trap_as_ref(arg0):
    _wasm_trap_as_ref = libiwasm.wasm_trap_as_ref
    _wasm_trap_as_ref.restype = POINTER(wasm_ref_t)
    _wasm_trap_as_ref.argtypes = [POINTER(wasm_trap_t)]
    return _wasm_trap_as_ref(arg0)

def wasm_ref_as_trap(arg0):
    _wasm_ref_as_trap = libiwasm.wasm_ref_as_trap
    _wasm_ref_as_trap.restype = POINTER(wasm_trap_t)
    _wasm_ref_as_trap.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_trap(arg0)

def wasm_trap_as_ref_const(arg0):
    _wasm_trap_as_ref_const = libiwasm.wasm_trap_as_ref_const
    _wasm_trap_as_ref_const.restype = POINTER(wasm_ref_t)
    _wasm_trap_as_ref_const.argtypes = [POINTER(wasm_trap_t)]
    return _wasm_trap_as_ref_const(arg0)

def wasm_ref_as_trap_const(arg0):
    _wasm_ref_as_trap_const = libiwasm.wasm_ref_as_trap_const
    _wasm_ref_as_trap_const.restype = POINTER(wasm_trap_t)
    _wasm_ref_as_trap_const.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_trap_const(arg0)

def wasm_trap_new(arg0,arg1):
    _wasm_trap_new = libiwasm.wasm_trap_new
    _wasm_trap_new.restype = POINTER(wasm_trap_t)
    _wasm_trap_new.argtypes = [POINTER(wasm_store_t),POINTER(wasm_message_t)]
    return _wasm_trap_new(arg0,arg1)

def wasm_trap_message(arg0,arg1):
    _wasm_trap_message = libiwasm.wasm_trap_message
    _wasm_trap_message.restype = None
    _wasm_trap_message.argtypes = [POINTER(wasm_trap_t),POINTER(wasm_message_t)]
    return _wasm_trap_message(arg0,arg1)

def wasm_trap_origin(arg0):
    _wasm_trap_origin = libiwasm.wasm_trap_origin
    _wasm_trap_origin.restype = POINTER(wasm_frame_t)
    _wasm_trap_origin.argtypes = [POINTER(wasm_trap_t)]
    return _wasm_trap_origin(arg0)

def wasm_trap_trace(arg0,arg1):
    _wasm_trap_trace = libiwasm.wasm_trap_trace
    _wasm_trap_trace.restype = None
    _wasm_trap_trace.argtypes = [POINTER(wasm_trap_t),POINTER(wasm_frame_vec_t)]
    return _wasm_trap_trace(arg0,arg1)

class wasm_foreign_t(Structure):
    pass

def wasm_foreign_delete(arg0):
    _wasm_foreign_delete = libiwasm.wasm_foreign_delete
    _wasm_foreign_delete.restype = None
    _wasm_foreign_delete.argtypes = [POINTER(wasm_foreign_t)]
    return _wasm_foreign_delete(arg0)

def wasm_foreign_copy(arg0):
    _wasm_foreign_copy = libiwasm.wasm_foreign_copy
    _wasm_foreign_copy.restype = POINTER(wasm_foreign_t)
    _wasm_foreign_copy.argtypes = [POINTER(wasm_foreign_t)]
    return _wasm_foreign_copy(arg0)

def wasm_foreign_same(arg0,arg1):
    _wasm_foreign_same = libiwasm.wasm_foreign_same
    _wasm_foreign_same.restype = c_bool
    _wasm_foreign_same.argtypes = [POINTER(wasm_foreign_t),POINTER(wasm_foreign_t)]
    return _wasm_foreign_same(arg0,arg1)

def wasm_foreign_get_host_info(arg0):
    _wasm_foreign_get_host_info = libiwasm.wasm_foreign_get_host_info
    _wasm_foreign_get_host_info.restype = c_void_p
    _wasm_foreign_get_host_info.argtypes = [POINTER(wasm_foreign_t)]
    return _wasm_foreign_get_host_info(arg0)

def wasm_foreign_set_host_info(arg0,arg1):
    _wasm_foreign_set_host_info = libiwasm.wasm_foreign_set_host_info
    _wasm_foreign_set_host_info.restype = None
    _wasm_foreign_set_host_info.argtypes = [POINTER(wasm_foreign_t),c_void_p]
    return _wasm_foreign_set_host_info(arg0,arg1)

def wasm_foreign_set_host_info_with_finalizer(arg0,arg1,arg2):
    _wasm_foreign_set_host_info_with_finalizer = libiwasm.wasm_foreign_set_host_info_with_finalizer
    _wasm_foreign_set_host_info_with_finalizer.restype = None
    _wasm_foreign_set_host_info_with_finalizer.argtypes = [POINTER(wasm_foreign_t),c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_foreign_set_host_info_with_finalizer(arg0,arg1,arg2)

def wasm_foreign_as_ref(arg0):
    _wasm_foreign_as_ref = libiwasm.wasm_foreign_as_ref
    _wasm_foreign_as_ref.restype = POINTER(wasm_ref_t)
    _wasm_foreign_as_ref.argtypes = [POINTER(wasm_foreign_t)]
    return _wasm_foreign_as_ref(arg0)

def wasm_ref_as_foreign(arg0):
    _wasm_ref_as_foreign = libiwasm.wasm_ref_as_foreign
    _wasm_ref_as_foreign.restype = POINTER(wasm_foreign_t)
    _wasm_ref_as_foreign.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_foreign(arg0)

def wasm_foreign_as_ref_const(arg0):
    _wasm_foreign_as_ref_const = libiwasm.wasm_foreign_as_ref_const
    _wasm_foreign_as_ref_const.restype = POINTER(wasm_ref_t)
    _wasm_foreign_as_ref_const.argtypes = [POINTER(wasm_foreign_t)]
    return _wasm_foreign_as_ref_const(arg0)

def wasm_ref_as_foreign_const(arg0):
    _wasm_ref_as_foreign_const = libiwasm.wasm_ref_as_foreign_const
    _wasm_ref_as_foreign_const.restype = POINTER(wasm_foreign_t)
    _wasm_ref_as_foreign_const.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_foreign_const(arg0)

def wasm_foreign_new(arg0):
    _wasm_foreign_new = libiwasm.wasm_foreign_new
    _wasm_foreign_new.restype = POINTER(wasm_foreign_t)
    _wasm_foreign_new.argtypes = [POINTER(wasm_store_t)]
    return _wasm_foreign_new(arg0)

class WASMModuleCommon(Structure):
    pass

class WASMModuleCommon(Structure):
    pass

wasm_module_t = POINTER(WASMModuleCommon)

def wasm_module_new(arg0,arg1):
    _wasm_module_new = libiwasm.wasm_module_new
    _wasm_module_new.restype = POINTER(wasm_module_t)
    _wasm_module_new.argtypes = [POINTER(wasm_store_t),POINTER(wasm_byte_vec_t)]
    return _wasm_module_new(arg0,arg1)

def wasm_module_delete(arg0):
    _wasm_module_delete = libiwasm.wasm_module_delete
    _wasm_module_delete.restype = None
    _wasm_module_delete.argtypes = [POINTER(wasm_module_t)]
    return _wasm_module_delete(arg0)

def wasm_module_validate(arg0,arg1):
    _wasm_module_validate = libiwasm.wasm_module_validate
    _wasm_module_validate.restype = c_bool
    _wasm_module_validate.argtypes = [POINTER(wasm_store_t),POINTER(wasm_byte_vec_t)]
    return _wasm_module_validate(arg0,arg1)

def wasm_module_imports(arg0,arg1):
    _wasm_module_imports = libiwasm.wasm_module_imports
    _wasm_module_imports.restype = None
    _wasm_module_imports.argtypes = [POINTER(wasm_module_t),POINTER(wasm_importtype_vec_t)]
    return _wasm_module_imports(arg0,arg1)

def wasm_module_exports(arg0,arg1):
    _wasm_module_exports = libiwasm.wasm_module_exports
    _wasm_module_exports.restype = None
    _wasm_module_exports.argtypes = [POINTER(wasm_module_t),POINTER(wasm_exporttype_vec_t)]
    return _wasm_module_exports(arg0,arg1)

def wasm_module_serialize(arg0,arg1):
    _wasm_module_serialize = libiwasm.wasm_module_serialize
    _wasm_module_serialize.restype = None
    _wasm_module_serialize.argtypes = [POINTER(wasm_module_t),POINTER(wasm_byte_vec_t)]
    return _wasm_module_serialize(arg0,arg1)

def wasm_module_deserialize(arg0,arg1):
    _wasm_module_deserialize = libiwasm.wasm_module_deserialize
    _wasm_module_deserialize.restype = POINTER(wasm_module_t)
    _wasm_module_deserialize.argtypes = [POINTER(wasm_store_t),POINTER(wasm_byte_vec_t)]
    return _wasm_module_deserialize(arg0,arg1)

class wasm_func_t(Structure):
    pass

def wasm_func_delete(arg0):
    _wasm_func_delete = libiwasm.wasm_func_delete
    _wasm_func_delete.restype = None
    _wasm_func_delete.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_delete(arg0)

def wasm_func_copy(arg0):
    _wasm_func_copy = libiwasm.wasm_func_copy
    _wasm_func_copy.restype = POINTER(wasm_func_t)
    _wasm_func_copy.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_copy(arg0)

def wasm_func_same(arg0,arg1):
    _wasm_func_same = libiwasm.wasm_func_same
    _wasm_func_same.restype = c_bool
    _wasm_func_same.argtypes = [POINTER(wasm_func_t),POINTER(wasm_func_t)]
    return _wasm_func_same(arg0,arg1)

def wasm_func_get_host_info(arg0):
    _wasm_func_get_host_info = libiwasm.wasm_func_get_host_info
    _wasm_func_get_host_info.restype = c_void_p
    _wasm_func_get_host_info.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_get_host_info(arg0)

def wasm_func_set_host_info(arg0,arg1):
    _wasm_func_set_host_info = libiwasm.wasm_func_set_host_info
    _wasm_func_set_host_info.restype = None
    _wasm_func_set_host_info.argtypes = [POINTER(wasm_func_t),c_void_p]
    return _wasm_func_set_host_info(arg0,arg1)

def wasm_func_set_host_info_with_finalizer(arg0,arg1,arg2):
    _wasm_func_set_host_info_with_finalizer = libiwasm.wasm_func_set_host_info_with_finalizer
    _wasm_func_set_host_info_with_finalizer.restype = None
    _wasm_func_set_host_info_with_finalizer.argtypes = [POINTER(wasm_func_t),c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_func_set_host_info_with_finalizer(arg0,arg1,arg2)

def wasm_func_as_ref(arg0):
    _wasm_func_as_ref = libiwasm.wasm_func_as_ref
    _wasm_func_as_ref.restype = POINTER(wasm_ref_t)
    _wasm_func_as_ref.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_as_ref(arg0)

def wasm_ref_as_func(arg0):
    _wasm_ref_as_func = libiwasm.wasm_ref_as_func
    _wasm_ref_as_func.restype = POINTER(wasm_func_t)
    _wasm_ref_as_func.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_func(arg0)

def wasm_func_as_ref_const(arg0):
    _wasm_func_as_ref_const = libiwasm.wasm_func_as_ref_const
    _wasm_func_as_ref_const.restype = POINTER(wasm_ref_t)
    _wasm_func_as_ref_const.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_as_ref_const(arg0)

def wasm_ref_as_func_const(arg0):
    _wasm_ref_as_func_const = libiwasm.wasm_ref_as_func_const
    _wasm_ref_as_func_const.restype = POINTER(wasm_func_t)
    _wasm_ref_as_func_const.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_func_const(arg0)

wasm_func_callback_t = CFUNCTYPE(c_void_p,POINTER(wasm_val_vec_t),POINTER(wasm_val_vec_t))

wasm_func_callback_with_env_t = CFUNCTYPE(c_void_p,c_void_p,POINTER(wasm_val_vec_t),POINTER(wasm_val_vec_t))

def wasm_func_new(arg0,arg1,arg2):
    _wasm_func_new = libiwasm.wasm_func_new
    _wasm_func_new.restype = POINTER(wasm_func_t)
    _wasm_func_new.argtypes = [POINTER(wasm_store_t),POINTER(wasm_functype_t),wasm_func_callback_t]
    return _wasm_func_new(arg0,arg1,arg2)

def wasm_func_new_with_env(arg0,arg1,arg2,arg3,arg4):
    _wasm_func_new_with_env = libiwasm.wasm_func_new_with_env
    _wasm_func_new_with_env.restype = POINTER(wasm_func_t)
    _wasm_func_new_with_env.argtypes = [POINTER(wasm_store_t),POINTER(wasm_functype_t),wasm_func_callback_with_env_t,c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_func_new_with_env(arg0,arg1,arg2,arg3,arg4)

def wasm_func_type(arg0):
    _wasm_func_type = libiwasm.wasm_func_type
    _wasm_func_type.restype = POINTER(wasm_functype_t)
    _wasm_func_type.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_type(arg0)

def wasm_func_param_arity(arg0):
    _wasm_func_param_arity = libiwasm.wasm_func_param_arity
    _wasm_func_param_arity.restype = c_size_t
    _wasm_func_param_arity.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_param_arity(arg0)

def wasm_func_result_arity(arg0):
    _wasm_func_result_arity = libiwasm.wasm_func_result_arity
    _wasm_func_result_arity.restype = c_size_t
    _wasm_func_result_arity.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_result_arity(arg0)

def wasm_func_call(arg0,arg1,arg2):
    _wasm_func_call = libiwasm.wasm_func_call
    _wasm_func_call.restype = POINTER(wasm_trap_t)
    _wasm_func_call.argtypes = [POINTER(wasm_func_t),POINTER(wasm_val_vec_t),POINTER(wasm_val_vec_t)]
    return _wasm_func_call(arg0,arg1,arg2)

class wasm_global_t(Structure):
    pass

def wasm_global_delete(arg0):
    _wasm_global_delete = libiwasm.wasm_global_delete
    _wasm_global_delete.restype = None
    _wasm_global_delete.argtypes = [POINTER(wasm_global_t)]
    return _wasm_global_delete(arg0)

def wasm_global_copy(arg0):
    _wasm_global_copy = libiwasm.wasm_global_copy
    _wasm_global_copy.restype = POINTER(wasm_global_t)
    _wasm_global_copy.argtypes = [POINTER(wasm_global_t)]
    return _wasm_global_copy(arg0)

def wasm_global_same(arg0,arg1):
    _wasm_global_same = libiwasm.wasm_global_same
    _wasm_global_same.restype = c_bool
    _wasm_global_same.argtypes = [POINTER(wasm_global_t),POINTER(wasm_global_t)]
    return _wasm_global_same(arg0,arg1)

def wasm_global_get_host_info(arg0):
    _wasm_global_get_host_info = libiwasm.wasm_global_get_host_info
    _wasm_global_get_host_info.restype = c_void_p
    _wasm_global_get_host_info.argtypes = [POINTER(wasm_global_t)]
    return _wasm_global_get_host_info(arg0)

def wasm_global_set_host_info(arg0,arg1):
    _wasm_global_set_host_info = libiwasm.wasm_global_set_host_info
    _wasm_global_set_host_info.restype = None
    _wasm_global_set_host_info.argtypes = [POINTER(wasm_global_t),c_void_p]
    return _wasm_global_set_host_info(arg0,arg1)

def wasm_global_set_host_info_with_finalizer(arg0,arg1,arg2):
    _wasm_global_set_host_info_with_finalizer = libiwasm.wasm_global_set_host_info_with_finalizer
    _wasm_global_set_host_info_with_finalizer.restype = None
    _wasm_global_set_host_info_with_finalizer.argtypes = [POINTER(wasm_global_t),c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_global_set_host_info_with_finalizer(arg0,arg1,arg2)

def wasm_global_as_ref(arg0):
    _wasm_global_as_ref = libiwasm.wasm_global_as_ref
    _wasm_global_as_ref.restype = POINTER(wasm_ref_t)
    _wasm_global_as_ref.argtypes = [POINTER(wasm_global_t)]
    return _wasm_global_as_ref(arg0)

def wasm_ref_as_global(arg0):
    _wasm_ref_as_global = libiwasm.wasm_ref_as_global
    _wasm_ref_as_global.restype = POINTER(wasm_global_t)
    _wasm_ref_as_global.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_global(arg0)

def wasm_global_as_ref_const(arg0):
    _wasm_global_as_ref_const = libiwasm.wasm_global_as_ref_const
    _wasm_global_as_ref_const.restype = POINTER(wasm_ref_t)
    _wasm_global_as_ref_const.argtypes = [POINTER(wasm_global_t)]
    return _wasm_global_as_ref_const(arg0)

def wasm_ref_as_global_const(arg0):
    _wasm_ref_as_global_const = libiwasm.wasm_ref_as_global_const
    _wasm_ref_as_global_const.restype = POINTER(wasm_global_t)
    _wasm_ref_as_global_const.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_global_const(arg0)

def wasm_global_new(arg0,arg1,arg2):
    _wasm_global_new = libiwasm.wasm_global_new
    _wasm_global_new.restype = POINTER(wasm_global_t)
    _wasm_global_new.argtypes = [POINTER(wasm_store_t),POINTER(wasm_globaltype_t),POINTER(wasm_val_t)]
    return _wasm_global_new(arg0,arg1,arg2)

def wasm_global_type(arg0):
    _wasm_global_type = libiwasm.wasm_global_type
    _wasm_global_type.restype = POINTER(wasm_globaltype_t)
    _wasm_global_type.argtypes = [POINTER(wasm_global_t)]
    return _wasm_global_type(arg0)

def wasm_global_get(arg0,arg1):
    _wasm_global_get = libiwasm.wasm_global_get
    _wasm_global_get.restype = None
    _wasm_global_get.argtypes = [POINTER(wasm_global_t),POINTER(wasm_val_t)]
    return _wasm_global_get(arg0,arg1)

def wasm_global_set(arg0,arg1):
    _wasm_global_set = libiwasm.wasm_global_set
    _wasm_global_set.restype = None
    _wasm_global_set.argtypes = [POINTER(wasm_global_t),POINTER(wasm_val_t)]
    return _wasm_global_set(arg0,arg1)

class wasm_table_t(Structure):
    pass

def wasm_table_delete(arg0):
    _wasm_table_delete = libiwasm.wasm_table_delete
    _wasm_table_delete.restype = None
    _wasm_table_delete.argtypes = [POINTER(wasm_table_t)]
    return _wasm_table_delete(arg0)

def wasm_table_copy(arg0):
    _wasm_table_copy = libiwasm.wasm_table_copy
    _wasm_table_copy.restype = POINTER(wasm_table_t)
    _wasm_table_copy.argtypes = [POINTER(wasm_table_t)]
    return _wasm_table_copy(arg0)

def wasm_table_same(arg0,arg1):
    _wasm_table_same = libiwasm.wasm_table_same
    _wasm_table_same.restype = c_bool
    _wasm_table_same.argtypes = [POINTER(wasm_table_t),POINTER(wasm_table_t)]
    return _wasm_table_same(arg0,arg1)

def wasm_table_get_host_info(arg0):
    _wasm_table_get_host_info = libiwasm.wasm_table_get_host_info
    _wasm_table_get_host_info.restype = c_void_p
    _wasm_table_get_host_info.argtypes = [POINTER(wasm_table_t)]
    return _wasm_table_get_host_info(arg0)

def wasm_table_set_host_info(arg0,arg1):
    _wasm_table_set_host_info = libiwasm.wasm_table_set_host_info
    _wasm_table_set_host_info.restype = None
    _wasm_table_set_host_info.argtypes = [POINTER(wasm_table_t),c_void_p]
    return _wasm_table_set_host_info(arg0,arg1)

def wasm_table_set_host_info_with_finalizer(arg0,arg1,arg2):
    _wasm_table_set_host_info_with_finalizer = libiwasm.wasm_table_set_host_info_with_finalizer
    _wasm_table_set_host_info_with_finalizer.restype = None
    _wasm_table_set_host_info_with_finalizer.argtypes = [POINTER(wasm_table_t),c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_table_set_host_info_with_finalizer(arg0,arg1,arg2)

def wasm_table_as_ref(arg0):
    _wasm_table_as_ref = libiwasm.wasm_table_as_ref
    _wasm_table_as_ref.restype = POINTER(wasm_ref_t)
    _wasm_table_as_ref.argtypes = [POINTER(wasm_table_t)]
    return _wasm_table_as_ref(arg0)

def wasm_ref_as_table(arg0):
    _wasm_ref_as_table = libiwasm.wasm_ref_as_table
    _wasm_ref_as_table.restype = POINTER(wasm_table_t)
    _wasm_ref_as_table.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_table(arg0)

def wasm_table_as_ref_const(arg0):
    _wasm_table_as_ref_const = libiwasm.wasm_table_as_ref_const
    _wasm_table_as_ref_const.restype = POINTER(wasm_ref_t)
    _wasm_table_as_ref_const.argtypes = [POINTER(wasm_table_t)]
    return _wasm_table_as_ref_const(arg0)

def wasm_ref_as_table_const(arg0):
    _wasm_ref_as_table_const = libiwasm.wasm_ref_as_table_const
    _wasm_ref_as_table_const.restype = POINTER(wasm_table_t)
    _wasm_ref_as_table_const.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_table_const(arg0)

wasm_table_size_t = c_uint32

def wasm_table_new(arg0,arg1,arg2):
    _wasm_table_new = libiwasm.wasm_table_new
    _wasm_table_new.restype = POINTER(wasm_table_t)
    _wasm_table_new.argtypes = [POINTER(wasm_store_t),POINTER(wasm_tabletype_t),POINTER(wasm_ref_t)]
    return _wasm_table_new(arg0,arg1,arg2)

def wasm_table_type(arg0):
    _wasm_table_type = libiwasm.wasm_table_type
    _wasm_table_type.restype = POINTER(wasm_tabletype_t)
    _wasm_table_type.argtypes = [POINTER(wasm_table_t)]
    return _wasm_table_type(arg0)

def wasm_table_get(arg0,arg1):
    _wasm_table_get = libiwasm.wasm_table_get
    _wasm_table_get.restype = POINTER(wasm_ref_t)
    _wasm_table_get.argtypes = [POINTER(wasm_table_t),wasm_table_size_t]
    return _wasm_table_get(arg0,arg1)

def wasm_table_set(arg0,arg1,arg2):
    _wasm_table_set = libiwasm.wasm_table_set
    _wasm_table_set.restype = c_bool
    _wasm_table_set.argtypes = [POINTER(wasm_table_t),wasm_table_size_t,POINTER(wasm_ref_t)]
    return _wasm_table_set(arg0,arg1,arg2)

def wasm_table_size(arg0):
    _wasm_table_size = libiwasm.wasm_table_size
    _wasm_table_size.restype = wasm_table_size_t
    _wasm_table_size.argtypes = [POINTER(wasm_table_t)]
    return _wasm_table_size(arg0)

def wasm_table_grow(arg0,arg1,arg2):
    _wasm_table_grow = libiwasm.wasm_table_grow
    _wasm_table_grow.restype = c_bool
    _wasm_table_grow.argtypes = [POINTER(wasm_table_t),wasm_table_size_t,POINTER(wasm_ref_t)]
    return _wasm_table_grow(arg0,arg1,arg2)

class wasm_memory_t(Structure):
    pass

def wasm_memory_delete(arg0):
    _wasm_memory_delete = libiwasm.wasm_memory_delete
    _wasm_memory_delete.restype = None
    _wasm_memory_delete.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_delete(arg0)

def wasm_memory_copy(arg0):
    _wasm_memory_copy = libiwasm.wasm_memory_copy
    _wasm_memory_copy.restype = POINTER(wasm_memory_t)
    _wasm_memory_copy.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_copy(arg0)

def wasm_memory_same(arg0,arg1):
    _wasm_memory_same = libiwasm.wasm_memory_same
    _wasm_memory_same.restype = c_bool
    _wasm_memory_same.argtypes = [POINTER(wasm_memory_t),POINTER(wasm_memory_t)]
    return _wasm_memory_same(arg0,arg1)

def wasm_memory_get_host_info(arg0):
    _wasm_memory_get_host_info = libiwasm.wasm_memory_get_host_info
    _wasm_memory_get_host_info.restype = c_void_p
    _wasm_memory_get_host_info.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_get_host_info(arg0)

def wasm_memory_set_host_info(arg0,arg1):
    _wasm_memory_set_host_info = libiwasm.wasm_memory_set_host_info
    _wasm_memory_set_host_info.restype = None
    _wasm_memory_set_host_info.argtypes = [POINTER(wasm_memory_t),c_void_p]
    return _wasm_memory_set_host_info(arg0,arg1)

def wasm_memory_set_host_info_with_finalizer(arg0,arg1,arg2):
    _wasm_memory_set_host_info_with_finalizer = libiwasm.wasm_memory_set_host_info_with_finalizer
    _wasm_memory_set_host_info_with_finalizer.restype = None
    _wasm_memory_set_host_info_with_finalizer.argtypes = [POINTER(wasm_memory_t),c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_memory_set_host_info_with_finalizer(arg0,arg1,arg2)

def wasm_memory_as_ref(arg0):
    _wasm_memory_as_ref = libiwasm.wasm_memory_as_ref
    _wasm_memory_as_ref.restype = POINTER(wasm_ref_t)
    _wasm_memory_as_ref.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_as_ref(arg0)

def wasm_ref_as_memory(arg0):
    _wasm_ref_as_memory = libiwasm.wasm_ref_as_memory
    _wasm_ref_as_memory.restype = POINTER(wasm_memory_t)
    _wasm_ref_as_memory.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_memory(arg0)

def wasm_memory_as_ref_const(arg0):
    _wasm_memory_as_ref_const = libiwasm.wasm_memory_as_ref_const
    _wasm_memory_as_ref_const.restype = POINTER(wasm_ref_t)
    _wasm_memory_as_ref_const.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_as_ref_const(arg0)

def wasm_ref_as_memory_const(arg0):
    _wasm_ref_as_memory_const = libiwasm.wasm_ref_as_memory_const
    _wasm_ref_as_memory_const.restype = POINTER(wasm_memory_t)
    _wasm_ref_as_memory_const.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_memory_const(arg0)

wasm_memory_pages_t = c_uint32

def wasm_memory_new(arg0,arg1):
    _wasm_memory_new = libiwasm.wasm_memory_new
    _wasm_memory_new.restype = POINTER(wasm_memory_t)
    _wasm_memory_new.argtypes = [POINTER(wasm_store_t),POINTER(wasm_memorytype_t)]
    return _wasm_memory_new(arg0,arg1)

def wasm_memory_type(arg0):
    _wasm_memory_type = libiwasm.wasm_memory_type
    _wasm_memory_type.restype = POINTER(wasm_memorytype_t)
    _wasm_memory_type.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_type(arg0)

def wasm_memory_data(arg0):
    _wasm_memory_data = libiwasm.wasm_memory_data
    _wasm_memory_data.restype = POINTER(c_ubyte)
    _wasm_memory_data.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_data(arg0)

def wasm_memory_data_size(arg0):
    _wasm_memory_data_size = libiwasm.wasm_memory_data_size
    _wasm_memory_data_size.restype = c_size_t
    _wasm_memory_data_size.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_data_size(arg0)

def wasm_memory_size(arg0):
    _wasm_memory_size = libiwasm.wasm_memory_size
    _wasm_memory_size.restype = wasm_memory_pages_t
    _wasm_memory_size.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_size(arg0)

def wasm_memory_grow(arg0,arg1):
    _wasm_memory_grow = libiwasm.wasm_memory_grow
    _wasm_memory_grow.restype = c_bool
    _wasm_memory_grow.argtypes = [POINTER(wasm_memory_t),wasm_memory_pages_t]
    return _wasm_memory_grow(arg0,arg1)

class wasm_extern_t(Structure):
    pass

def wasm_extern_delete(arg0):
    _wasm_extern_delete = libiwasm.wasm_extern_delete
    _wasm_extern_delete.restype = None
    _wasm_extern_delete.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_delete(arg0)

def wasm_extern_copy(arg0):
    _wasm_extern_copy = libiwasm.wasm_extern_copy
    _wasm_extern_copy.restype = POINTER(wasm_extern_t)
    _wasm_extern_copy.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_copy(arg0)

def wasm_extern_same(arg0,arg1):
    _wasm_extern_same = libiwasm.wasm_extern_same
    _wasm_extern_same.restype = c_bool
    _wasm_extern_same.argtypes = [POINTER(wasm_extern_t),POINTER(wasm_extern_t)]
    return _wasm_extern_same(arg0,arg1)

def wasm_extern_get_host_info(arg0):
    _wasm_extern_get_host_info = libiwasm.wasm_extern_get_host_info
    _wasm_extern_get_host_info.restype = c_void_p
    _wasm_extern_get_host_info.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_get_host_info(arg0)

def wasm_extern_set_host_info(arg0,arg1):
    _wasm_extern_set_host_info = libiwasm.wasm_extern_set_host_info
    _wasm_extern_set_host_info.restype = None
    _wasm_extern_set_host_info.argtypes = [POINTER(wasm_extern_t),c_void_p]
    return _wasm_extern_set_host_info(arg0,arg1)

def wasm_extern_set_host_info_with_finalizer(arg0,arg1,arg2):
    _wasm_extern_set_host_info_with_finalizer = libiwasm.wasm_extern_set_host_info_with_finalizer
    _wasm_extern_set_host_info_with_finalizer.restype = None
    _wasm_extern_set_host_info_with_finalizer.argtypes = [POINTER(wasm_extern_t),c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_extern_set_host_info_with_finalizer(arg0,arg1,arg2)

def wasm_extern_as_ref(arg0):
    _wasm_extern_as_ref = libiwasm.wasm_extern_as_ref
    _wasm_extern_as_ref.restype = POINTER(wasm_ref_t)
    _wasm_extern_as_ref.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_ref(arg0)

def wasm_ref_as_extern(arg0):
    _wasm_ref_as_extern = libiwasm.wasm_ref_as_extern
    _wasm_ref_as_extern.restype = POINTER(wasm_extern_t)
    _wasm_ref_as_extern.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_extern(arg0)

def wasm_extern_as_ref_const(arg0):
    _wasm_extern_as_ref_const = libiwasm.wasm_extern_as_ref_const
    _wasm_extern_as_ref_const.restype = POINTER(wasm_ref_t)
    _wasm_extern_as_ref_const.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_ref_const(arg0)

def wasm_ref_as_extern_const(arg0):
    _wasm_ref_as_extern_const = libiwasm.wasm_ref_as_extern_const
    _wasm_ref_as_extern_const.restype = POINTER(wasm_extern_t)
    _wasm_ref_as_extern_const.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_extern_const(arg0)

class wasm_extern_vec_t(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("data", POINTER(POINTER(wasm_extern_t))),
        ("num_elems", c_size_t),
        ("size_of_elem", c_size_t),
        ("lock", c_void_p),
    ]

    def __eq__(self, other):
        if not isinstance(other, wasm_extern_vec_t):
            return False
        return self.size == other.size and self.num_elems == other.num_elems and self.size_of_elem == other.size_of_elem

    def __repr__(self):
        ret = ""
        for i in range(self.num_elems):
                ret += str(dereference(self.data[i]))
                ret += " "
        return ret



def wasm_extern_vec_new_empty(arg0):
    _wasm_extern_vec_new_empty = libiwasm.wasm_extern_vec_new_empty
    _wasm_extern_vec_new_empty.restype = None
    _wasm_extern_vec_new_empty.argtypes = [POINTER(wasm_extern_vec_t)]
    return _wasm_extern_vec_new_empty(arg0)

def wasm_extern_vec_new_uninitialized(arg0,arg1):
    _wasm_extern_vec_new_uninitialized = libiwasm.wasm_extern_vec_new_uninitialized
    _wasm_extern_vec_new_uninitialized.restype = None
    _wasm_extern_vec_new_uninitialized.argtypes = [POINTER(wasm_extern_vec_t),c_size_t]
    return _wasm_extern_vec_new_uninitialized(arg0,arg1)

def wasm_extern_vec_new(arg0,arg1,arg2):
    _wasm_extern_vec_new = libiwasm.wasm_extern_vec_new
    _wasm_extern_vec_new.restype = None
    _wasm_extern_vec_new.argtypes = [POINTER(wasm_extern_vec_t),c_size_t,POINTER(POINTER(wasm_extern_t))]
    return _wasm_extern_vec_new(arg0,arg1,arg2)

def wasm_extern_vec_copy(arg0,arg1):
    _wasm_extern_vec_copy = libiwasm.wasm_extern_vec_copy
    _wasm_extern_vec_copy.restype = None
    _wasm_extern_vec_copy.argtypes = [POINTER(wasm_extern_vec_t),POINTER(wasm_extern_vec_t)]
    return _wasm_extern_vec_copy(arg0,arg1)

def wasm_extern_vec_delete(arg0):
    _wasm_extern_vec_delete = libiwasm.wasm_extern_vec_delete
    _wasm_extern_vec_delete.restype = None
    _wasm_extern_vec_delete.argtypes = [POINTER(wasm_extern_vec_t)]
    return _wasm_extern_vec_delete(arg0)

def wasm_extern_kind(arg0):
    _wasm_extern_kind = libiwasm.wasm_extern_kind
    _wasm_extern_kind.restype = wasm_externkind_t
    _wasm_extern_kind.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_kind(arg0)

def wasm_extern_type(arg0):
    _wasm_extern_type = libiwasm.wasm_extern_type
    _wasm_extern_type.restype = POINTER(wasm_externtype_t)
    _wasm_extern_type.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_type(arg0)

def wasm_func_as_extern(arg0):
    _wasm_func_as_extern = libiwasm.wasm_func_as_extern
    _wasm_func_as_extern.restype = POINTER(wasm_extern_t)
    _wasm_func_as_extern.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_as_extern(arg0)

def wasm_global_as_extern(arg0):
    _wasm_global_as_extern = libiwasm.wasm_global_as_extern
    _wasm_global_as_extern.restype = POINTER(wasm_extern_t)
    _wasm_global_as_extern.argtypes = [POINTER(wasm_global_t)]
    return _wasm_global_as_extern(arg0)

def wasm_table_as_extern(arg0):
    _wasm_table_as_extern = libiwasm.wasm_table_as_extern
    _wasm_table_as_extern.restype = POINTER(wasm_extern_t)
    _wasm_table_as_extern.argtypes = [POINTER(wasm_table_t)]
    return _wasm_table_as_extern(arg0)

def wasm_memory_as_extern(arg0):
    _wasm_memory_as_extern = libiwasm.wasm_memory_as_extern
    _wasm_memory_as_extern.restype = POINTER(wasm_extern_t)
    _wasm_memory_as_extern.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_as_extern(arg0)

def wasm_extern_as_func(arg0):
    _wasm_extern_as_func = libiwasm.wasm_extern_as_func
    _wasm_extern_as_func.restype = POINTER(wasm_func_t)
    _wasm_extern_as_func.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_func(arg0)

def wasm_extern_as_global(arg0):
    _wasm_extern_as_global = libiwasm.wasm_extern_as_global
    _wasm_extern_as_global.restype = POINTER(wasm_global_t)
    _wasm_extern_as_global.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_global(arg0)

def wasm_extern_as_table(arg0):
    _wasm_extern_as_table = libiwasm.wasm_extern_as_table
    _wasm_extern_as_table.restype = POINTER(wasm_table_t)
    _wasm_extern_as_table.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_table(arg0)

def wasm_extern_as_memory(arg0):
    _wasm_extern_as_memory = libiwasm.wasm_extern_as_memory
    _wasm_extern_as_memory.restype = POINTER(wasm_memory_t)
    _wasm_extern_as_memory.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_memory(arg0)

def wasm_func_as_extern_const(arg0):
    _wasm_func_as_extern_const = libiwasm.wasm_func_as_extern_const
    _wasm_func_as_extern_const.restype = POINTER(wasm_extern_t)
    _wasm_func_as_extern_const.argtypes = [POINTER(wasm_func_t)]
    return _wasm_func_as_extern_const(arg0)

def wasm_global_as_extern_const(arg0):
    _wasm_global_as_extern_const = libiwasm.wasm_global_as_extern_const
    _wasm_global_as_extern_const.restype = POINTER(wasm_extern_t)
    _wasm_global_as_extern_const.argtypes = [POINTER(wasm_global_t)]
    return _wasm_global_as_extern_const(arg0)

def wasm_table_as_extern_const(arg0):
    _wasm_table_as_extern_const = libiwasm.wasm_table_as_extern_const
    _wasm_table_as_extern_const.restype = POINTER(wasm_extern_t)
    _wasm_table_as_extern_const.argtypes = [POINTER(wasm_table_t)]
    return _wasm_table_as_extern_const(arg0)

def wasm_memory_as_extern_const(arg0):
    _wasm_memory_as_extern_const = libiwasm.wasm_memory_as_extern_const
    _wasm_memory_as_extern_const.restype = POINTER(wasm_extern_t)
    _wasm_memory_as_extern_const.argtypes = [POINTER(wasm_memory_t)]
    return _wasm_memory_as_extern_const(arg0)

def wasm_extern_as_func_const(arg0):
    _wasm_extern_as_func_const = libiwasm.wasm_extern_as_func_const
    _wasm_extern_as_func_const.restype = POINTER(wasm_func_t)
    _wasm_extern_as_func_const.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_func_const(arg0)

def wasm_extern_as_global_const(arg0):
    _wasm_extern_as_global_const = libiwasm.wasm_extern_as_global_const
    _wasm_extern_as_global_const.restype = POINTER(wasm_global_t)
    _wasm_extern_as_global_const.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_global_const(arg0)

def wasm_extern_as_table_const(arg0):
    _wasm_extern_as_table_const = libiwasm.wasm_extern_as_table_const
    _wasm_extern_as_table_const.restype = POINTER(wasm_table_t)
    _wasm_extern_as_table_const.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_table_const(arg0)

def wasm_extern_as_memory_const(arg0):
    _wasm_extern_as_memory_const = libiwasm.wasm_extern_as_memory_const
    _wasm_extern_as_memory_const.restype = POINTER(wasm_memory_t)
    _wasm_extern_as_memory_const.argtypes = [POINTER(wasm_extern_t)]
    return _wasm_extern_as_memory_const(arg0)

class wasm_instance_t(Structure):
    pass

def wasm_instance_delete(arg0):
    _wasm_instance_delete = libiwasm.wasm_instance_delete
    _wasm_instance_delete.restype = None
    _wasm_instance_delete.argtypes = [POINTER(wasm_instance_t)]
    return _wasm_instance_delete(arg0)

def wasm_instance_copy(arg0):
    _wasm_instance_copy = libiwasm.wasm_instance_copy
    _wasm_instance_copy.restype = POINTER(wasm_instance_t)
    _wasm_instance_copy.argtypes = [POINTER(wasm_instance_t)]
    return _wasm_instance_copy(arg0)

def wasm_instance_same(arg0,arg1):
    _wasm_instance_same = libiwasm.wasm_instance_same
    _wasm_instance_same.restype = c_bool
    _wasm_instance_same.argtypes = [POINTER(wasm_instance_t),POINTER(wasm_instance_t)]
    return _wasm_instance_same(arg0,arg1)

def wasm_instance_get_host_info(arg0):
    _wasm_instance_get_host_info = libiwasm.wasm_instance_get_host_info
    _wasm_instance_get_host_info.restype = c_void_p
    _wasm_instance_get_host_info.argtypes = [POINTER(wasm_instance_t)]
    return _wasm_instance_get_host_info(arg0)

def wasm_instance_set_host_info(arg0,arg1):
    _wasm_instance_set_host_info = libiwasm.wasm_instance_set_host_info
    _wasm_instance_set_host_info.restype = None
    _wasm_instance_set_host_info.argtypes = [POINTER(wasm_instance_t),c_void_p]
    return _wasm_instance_set_host_info(arg0,arg1)

def wasm_instance_set_host_info_with_finalizer(arg0,arg1,arg2):
    _wasm_instance_set_host_info_with_finalizer = libiwasm.wasm_instance_set_host_info_with_finalizer
    _wasm_instance_set_host_info_with_finalizer.restype = None
    _wasm_instance_set_host_info_with_finalizer.argtypes = [POINTER(wasm_instance_t),c_void_p,CFUNCTYPE(None,c_void_p)]
    return _wasm_instance_set_host_info_with_finalizer(arg0,arg1,arg2)

def wasm_instance_as_ref(arg0):
    _wasm_instance_as_ref = libiwasm.wasm_instance_as_ref
    _wasm_instance_as_ref.restype = POINTER(wasm_ref_t)
    _wasm_instance_as_ref.argtypes = [POINTER(wasm_instance_t)]
    return _wasm_instance_as_ref(arg0)

def wasm_ref_as_instance(arg0):
    _wasm_ref_as_instance = libiwasm.wasm_ref_as_instance
    _wasm_ref_as_instance.restype = POINTER(wasm_instance_t)
    _wasm_ref_as_instance.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_instance(arg0)

def wasm_instance_as_ref_const(arg0):
    _wasm_instance_as_ref_const = libiwasm.wasm_instance_as_ref_const
    _wasm_instance_as_ref_const.restype = POINTER(wasm_ref_t)
    _wasm_instance_as_ref_const.argtypes = [POINTER(wasm_instance_t)]
    return _wasm_instance_as_ref_const(arg0)

def wasm_ref_as_instance_const(arg0):
    _wasm_ref_as_instance_const = libiwasm.wasm_ref_as_instance_const
    _wasm_ref_as_instance_const.restype = POINTER(wasm_instance_t)
    _wasm_ref_as_instance_const.argtypes = [POINTER(wasm_ref_t)]
    return _wasm_ref_as_instance_const(arg0)

def wasm_instance_new(arg0,arg1,arg2,arg3):
    _wasm_instance_new = libiwasm.wasm_instance_new
    _wasm_instance_new.restype = POINTER(wasm_instance_t)
    _wasm_instance_new.argtypes = [POINTER(wasm_store_t),POINTER(wasm_module_t),POINTER(wasm_extern_vec_t),POINTER(POINTER(wasm_trap_t))]
    return _wasm_instance_new(arg0,arg1,arg2,arg3)

def wasm_instance_new_with_args(arg0,arg1,arg2,arg3,arg4,arg5):
    _wasm_instance_new_with_args = libiwasm.wasm_instance_new_with_args
    _wasm_instance_new_with_args.restype = POINTER(wasm_instance_t)
    _wasm_instance_new_with_args.argtypes = [POINTER(wasm_store_t),POINTER(wasm_module_t),POINTER(wasm_extern_vec_t),POINTER(POINTER(wasm_trap_t)),c_uint32,c_uint32]
    return _wasm_instance_new_with_args(arg0,arg1,arg2,arg3,arg4,arg5)

def wasm_instance_exports(arg0,arg1):
    _wasm_instance_exports = libiwasm.wasm_instance_exports
    _wasm_instance_exports.restype = None
    _wasm_instance_exports.argtypes = [POINTER(wasm_instance_t),POINTER(wasm_extern_vec_t)]
    return _wasm_instance_exports(arg0,arg1)
