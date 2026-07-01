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
import unittest
from venv import create

from wamr.wasmcapi.ffi import *

# It is a module likes:
# (module
#   (import "mod" "g0" (global i32))
#   (import "mod" "f0" (func (param f32) (result f64)))
#
#   (func (export "f1") (param i32 i64))
#   (global (export "g1") (mut f32) (f32.const 3.14))
#   (memory 1 2)
#   (table 1 funcref)
# )
MODULE_BINARY = (
    b"\x00asm\x01\x00\x00\x00\x01\x0b\x02`\x01}\x01|`\x02\x7f~\x00"
    b"\x02\x14\x02\x03mod\x02g0\x03\x7f\x00\x03mod\x02f0\x00\x00\x03"
    b"\x02\x01\x01\x04\x04\x01p\x00\x01\x05\x04\x01\x01\x01\x02\x06\t"
    b"\x01}\x01C\xc3\xf5H@\x0b\x07\x0b\x02\x02f1\x00\x01\x02g1\x03\x01\n"
    b"\x04\x01\x02\x00\x0b"
)


@wasm_func_cb_decl
def callback(args, results):
    # pylint: disable=unused-argument
    print("summer")


@wasm_func_with_env_cb_decl
def callback_with_env(env, args, results):
    # pylint: disable=unused-argument
    print("summer")


class BasicTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._wasm_engine = wasm_engine_new()
        cls._wasm_store = wasm_store_new(cls._wasm_engine)

    def assertIsNullPointer(self, c_pointer):
        if not is_null_pointer(c_pointer):
            self.fail("not a null pointer")

    def assertIsNotNullPointer(self, c_pointer):
        if is_null_pointer(c_pointer):
            self.fail("not a non-null pointer")

    def test_wasm_valkind(self):
        self.assertEqual(
            [WASM_I32, WASM_I64, WASM_F32, WASM_F64, WASM_EXTERNREF, WASM_FUNCREF],
            [0, 1, 2, 3, 128, 129],
        )

    def test_wasm_valtype_new_pos(self):
        vt = wasm_valtype_new(WASM_I32)
        self.assertIsNotNullPointer(vt)
        wasm_valtype_delete(vt)

    def test_wasm_valtype_new_neg(self):
        vt = wasm_valtype_new(37)
        self.assertIsNullPointer(vt)
        wasm_valtype_delete(vt)

    def test_wasm_valtype_kind_pos(self):
        vt = wasm_valtype_new(WASM_I64)
        self.assertEqual(wasm_valtype_kind(vt), WASM_I64)
        wasm_valtype_delete(vt)

    def test_wasm_valtype_kind_neg(self):
        wasm_valtype_kind(create_null_pointer(wasm_valtype_t))

    def test_wasm_valtype_delete_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        wasm_valtype_delete(vt)

    def test_wasm_valtype_delete_neg(self):
        wasm_valtype_delete(create_null_pointer(wasm_valtype_t))

    def test_wasm_valtype_copy_pos(self):
        vt1 = wasm_valtype_new(WASM_FUNCREF)
        vt2 = wasm_valtype_copy(vt1)

        self.assertIsNotNone(vt1)
        self.assertIsNotNullPointer(vt1)
        self.assertEqual(dereference(vt1), dereference(vt2))

        wasm_valtype_delete(vt1)
        wasm_valtype_delete(vt2)

    def test_wasm_valtype_copy_neg(self):
        vt = wasm_valtype_copy(create_null_pointer(wasm_valtype_t))
        self.assertIsNotNone(vt)
        self.assertIsNullPointer(vt)

    def test_list_to_carray(self):
        v1 = wasm_valtype_new(WASM_I64)
        v2 = wasm_valtype_new(WASM_F32)
        v3 = wasm_valtype_new(WASM_FUNCREF)
        data = list_to_carray(c.POINTER(wasm_valtype_t), v1, v2, v3)

        self.assertIsNotNone(data)
        self.assertTrue(isinstance(data, c.Array))
        self.assertEqual(data._length_, 3)
        self.assertEqual(dereference(data[0]), dereference(v1))
        self.assertEqual(dereference(data[1]), dereference(v2))
        self.assertEqual(dereference(data[2]), dereference(v3))

        wasm_valtype_delete(v1)
        wasm_valtype_delete(v2)
        wasm_valtype_delete(v3)

    def test_wasm_valtype_vec_new_pos(self):
        def_vt_list = [
            wasm_valtype_new(WASM_I32),
            wasm_valtype_new(WASM_F64),
            wasm_valtype_new(WASM_FUNCREF),
        ]
        data = list_to_carray(c.POINTER(wasm_valtype_t), *def_vt_list)
        vt_vec = wasm_valtype_vec_t()
        wasm_valtype_vec_new(vt_vec, 3, data)

        self.assertEqual(vt_vec.size, 3)
        self.assertEqual(vt_vec.num_elems, 3)
        self.assertIsNotNullPointer(vt_vec.data)

        ret_vt_list = wasm_vec_to_list(vt_vec)
        ret_vt_list = [dereference(vt) for vt in ret_vt_list]
        def_vt_list = [dereference(vt) for vt in def_vt_list]
        self.assertEqual(ret_vt_list, def_vt_list)

        wasm_valtype_vec_delete(vt_vec)

    def test_wasm_valtype_vec_new_neg(self):
        data = list_to_carray(
            c.POINTER(wasm_valtype_t),
            wasm_valtype_new(WASM_I32),
            wasm_valtype_new(WASM_F64),
            wasm_valtype_new(WASM_FUNCREF),
        )
        vt_vec = wasm_valtype_vec_t()
        wasm_valtype_vec_new(vt_vec, 1_000_000_000, data)

        self.assertEqual(vt_vec.size, 0)
        self.assertIsNullPointer(vt_vec.data)

        wasm_valtype_vec_delete(vt_vec)

    def test_wasm_valtype_vec_new_null_out(self):
        data = list_to_carray(
            c.POINTER(wasm_valtype_t),
            wasm_valtype_new(WASM_I32),
            wasm_valtype_new(WASM_F64),
            wasm_valtype_new(WASM_FUNCREF),
        )
        wasm_valtype_vec_new(create_null_pointer(wasm_valtype_vec_t), 10, data)

    def test_wasm_valtype_vec_new_null_data(self):
        vt_vec = wasm_valtype_vec_t()
        wasm_valtype_vec_new(vt_vec, 3, create_null_pointer(wasm_valtype_t))
        self.assertIsNotNone(vt_vec)
        self.assertIsNotNullPointer(c.pointer(vt_vec))

    def test_wasm_valtype_vec_new_uninitialized_pos(self):
        vt_vec = wasm_valtype_vec_t()
        wasm_valtype_vec_new_uninitialized((vt_vec), 2)
        self.assertEqual(2, vt_vec.size)
        wasm_valtype_vec_delete(vt_vec)

    def test_wasm_valtype_vec_new_uninitialized_neg(self):
        vt_vec = wasm_valtype_vec_t()
        wasm_valtype_vec_new_uninitialized(vt_vec, 1_000_000_000)
        self.assertEqual(vt_vec.size, 0)
        self.assertIsNullPointer(vt_vec.data)
        wasm_valtype_vec_delete(vt_vec)

    def test_wasm_valtype_vec_new_uninitialized_null_out(self):
        wasm_valtype_vec_new_uninitialized(create_null_pointer(wasm_valtype_vec_t), 2)

    def test_wasm_valtype_vec_new_empty_pos(self):
        vt_vec = wasm_valtype_vec_t()
        wasm_valtype_vec_new_empty(vt_vec)
        self.assertEqual(0, vt_vec.size)
        self.assertIsNullPointer(vt_vec.data)
        wasm_valtype_vec_delete(vt_vec)

    def test_wasm_valtype_vec_new_empty_neg(self):
        wasm_valtype_vec_new_empty(create_null_pointer(wasm_valtype_vec_t))

    def test_wasm_valtype_vec_copy_pos(self):
        vt_vec1 = wasm_valtype_vec_t()
        vt1 = wasm_valtype_new(WASM_F32)
        vt2 = wasm_valtype_new(WASM_I32)
        data = list_to_carray(c.POINTER(wasm_valtype_t), vt1, vt2)
        wasm_valtype_vec_new(vt_vec1, 2, data)

        vt_vec2 = wasm_valtype_vec_t()
        wasm_valtype_vec_copy(vt_vec2, vt_vec1)

        print(f"{vt_vec1} --> {vt_vec2}")

        self.assertEqual(vt_vec2.size, 2)
        self.assertEqual(vt_vec2.num_elems, 2)
        self.assertEqual(dereference(vt_vec2.data[0]), dereference(vt1))
        self.assertEqual(dereference(vt_vec2.data[1]), dereference(vt2))

        wasm_valtype_vec_delete(vt_vec1)
        wasm_valtype_vec_delete(vt_vec2)

    def test_wasm_valtype_vec_copy_null_src(self):
        dst = wasm_valtype_vec_t()
        wasm_valtype_vec_copy(dst, create_null_pointer(wasm_valtype_vec_t))
        self.assertIsNotNullPointer(c.pointer(dst))
        self.assertIsNullPointer(dst.data)

    def test_wasm_valtype_vec_copy_null_dst(self):
        src = wasm_valtype_vec_t()
        wasm_valtype_vec_new_empty(src)
        wasm_valtype_vec_copy(create_null_pointer(wasm_valtype_vec_t), src)
        wasm_valtype_vec_delete(src)

    def test_wasm_valtype_vec_delete_pos(self):
        vt_vec = wasm_valtype_vec_t()
        wasm_valtype_vec_new_uninitialized(vt_vec, 10)
        wasm_valtype_vec_delete(vt_vec)

        vt_vec = wasm_valtype_vec_t()
        wasm_valtype_vec_new_empty(vt_vec)
        wasm_valtype_vec_delete(vt_vec)

    def test_wasm_valtype_vec_delete_neg(self):
        wasm_valtype_vec_delete(create_null_pointer(wasm_valtype_vec_t))

    def test_wasm_functype_new_0_0(self):
        ft = wasm_functype_new_0_0()

        self.assertIsNotNullPointer(ft)
        self.assertEqual(0, dereference(wasm_functype_params(ft)).size)
        self.assertEqual(0, dereference(wasm_functype_results(ft)).size)

        wasm_functype_delete(ft)

    def test_wasm_functype_new_1_0(self):
        vt = wasm_valtype_new(WASM_I64)
        ft = wasm_functype_new_1_0(vt)

        self.assertIsNotNullPointer(ft)
        params = wasm_vec_to_list(wasm_functype_params(ft))
        self.assertEqual([dereference(p) for p in params], [dereference(vt)])

        wasm_functype_delete(ft)

    def test_wasm_functype_new_2_0(self):
        vt1 = wasm_valtype_new(WASM_I64)
        vt2 = wasm_valtype_new(WASM_F64)
        ft = wasm_functype_new_2_0(vt1, vt2)

        self.assertIsNotNullPointer(ft)
        self.assertEqual(2, dereference(wasm_functype_params(ft)).size)
        self.assertEqual(0, dereference(wasm_functype_results(ft)).size)

        wasm_functype_delete(ft)

    def test_wasm_functype_new_3_0(self):
        vt_list = [
            wasm_valtype_new(WASM_I64),
            wasm_valtype_new(WASM_F64),
            wasm_valtype_new(WASM_I64),
        ]
        ft = wasm_functype_new_3_0(*vt_list)

        params = wasm_vec_to_list(wasm_functype_params(ft))
        self.assertEqual(
            [dereference(p) for p in params],
            [dereference(vt) for vt in vt_list],
        )

        wasm_functype_delete(ft)

    def test_wasm_functype_new_0_1(self):
        vt1 = wasm_valtype_new(WASM_I64)
        ft = wasm_functype_new_0_1(vt1)

        self.assertIsNotNullPointer(ft)
        self.assertEqual(0, dereference(wasm_functype_params(ft)).size)
        self.assertEqual(1, dereference(wasm_functype_results(ft)).size)

        wasm_functype_delete(ft)

    def test_wasm_functype_new_1_1(self):
        vt1 = wasm_valtype_new(WASM_I64)
        vt2 = wasm_valtype_new(WASM_F64)
        ft = wasm_functype_new_1_1(vt1, vt2)

        params = wasm_vec_to_list(wasm_functype_params(ft))
        self.assertEqual(dereference(params[0]), dereference(vt1))

        results = wasm_vec_to_list(wasm_functype_results(ft))
        self.assertEqual(dereference(results[0]), dereference(vt2))

        wasm_functype_delete(ft)

    def test_wasm_functype_new_2_1(self):
        vt_list = [
            wasm_valtype_new(WASM_I64),
            wasm_valtype_new(WASM_F64),
            wasm_valtype_new(WASM_I64),
        ]
        ft = wasm_functype_new_2_1(*vt_list)

        self.assertIsNotNullPointer(ft)
        self.assertEqual(2, dereference(wasm_functype_params(ft)).size)
        self.assertEqual(1, dereference(wasm_functype_results(ft)).size)

        wasm_functype_delete(ft)

    def test_wasm_functype_new_3_1(self):
        vt_list = [
            wasm_valtype_new(WASM_I64),
            wasm_valtype_new(WASM_F64),
            wasm_valtype_new(WASM_I64),
            wasm_valtype_new(WASM_I32),
        ]
        ft = wasm_functype_new_3_1(*vt_list)

        params = wasm_vec_to_list(wasm_functype_params(ft))
        self.assertEqual(
            [dereference(p) for p in params], [dereference(vt) for vt in vt_list[:3]]
        )

        results = wasm_vec_to_list(wasm_functype_results(ft))
        self.assertEqual(dereference(results[0]), dereference(vt_list[-1]))

        wasm_functype_delete(ft)

    def test_wasm_functype_new_neg(self):
        ft = wasm_functype_new(
            create_null_pointer(wasm_valtype_vec_t),
            create_null_pointer(wasm_valtype_vec_t),
        )

        self.assertIsNotNullPointer(ft)

        wasm_functype_delete(ft)

    def test_wasm_functype_delete_pos(self):
        ft = wasm_functype_new_0_0()
        wasm_functype_delete(ft)

    def test_wasm_functype_delete_neg(self):
        wasm_functype_delete(create_null_pointer(wasm_functype_t))

    def test_wasm_functype_params_pos(self):
        vt_list = [
            wasm_valtype_new(WASM_I64),
            wasm_valtype_new(WASM_F64),
            wasm_valtype_new(WASM_I64),
        ]
        ft = wasm_functype_new_3_0(*vt_list)
        params = wasm_vec_to_list(wasm_functype_params(ft))

        self.assertEqual(
            [dereference(p) for p in params],
            [dereference(vt) for vt in vt_list],
        )

        wasm_functype_delete(ft)

    def test_wasm_functype_params_neg(self):
        params = wasm_functype_params(create_null_pointer(wasm_functype_t))
        self.assertIsNullPointer(params)

    def test_wasm_functype_results_pos(self):
        vt1 = wasm_valtype_new(WASM_I64)
        ft = wasm_functype_new_0_1(vt1)
        results = wasm_vec_to_list(wasm_functype_results(ft))

        self.assertEqual(dereference(results[0]), dereference(vt1))

        wasm_functype_delete(ft)

    def test_wasm_functype_results_neg(self):
        results = wasm_functype_results(create_null_pointer(wasm_functype_t))
        self.assertIsNullPointer(results)

    def test_wasm_functype_copy_pos(self):
        ft1 = wasm_functype_new_2_1(
            wasm_valtype_new(WASM_I64),
            wasm_valtype_new(WASM_F64),
            wasm_valtype_new(WASM_I64),
        )
        ft2 = wasm_functype_copy(ft1)

        self.assertIsNotNullPointer(ft2)
        self.assertEqual(2, dereference(wasm_functype_params(ft1)).size)
        self.assertEqual(1, dereference(wasm_functype_results(ft2)).size)

        wasm_functype_delete(ft1)
        wasm_functype_delete(ft2)

    def test_wasm_functype_copy_neg(self):
        ft2 = wasm_functype_copy(create_null_pointer(wasm_functype_t))
        self.assertIsNullPointer(ft2)
        wasm_functype_delete(ft2)

    def test_wasm_globaltype_new_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        gt = wasm_globaltype_new(vt, True)

        self.assertIsNotNullPointer(gt)

        wasm_globaltype_delete(gt)

    def test_wasm_globaltype_new_neg(self):
        gt = wasm_globaltype_new(create_null_pointer(wasm_valtype_t), True)
        self.assertIsNullPointer(gt)
        wasm_globaltype_delete(gt)

    def test_wasm_globaltype_delete_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        gt = wasm_globaltype_new(vt, False)
        wasm_globaltype_delete(gt)

    def test_wasm_globaltype_delete_neg(self):
        wasm_globaltype_delete(create_null_pointer(wasm_globaltype_t))

    def test_wasm_globaltype_content_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        gt = wasm_globaltype_new(vt, True)
        gt_ret = wasm_globaltype_content(gt)

        self.assertEqual(dereference(vt), dereference(gt_ret))

        wasm_globaltype_delete(gt)

    def test_wasm_globaltype_content_neg(self):
        gt_ret = wasm_globaltype_content(create_null_pointer(wasm_globaltype_t))
        self.assertIsNullPointer(gt_ret)

    def test_wasm_globaltype_mutability_pos(self):
        vt1 = wasm_valtype_new(WASM_F32)
        gt1 = wasm_globaltype_new(vt1, False)
        vt2 = wasm_valtype_new(WASM_F32)
        gt2 = wasm_globaltype_new(vt2, True)

        self.assertFalse(wasm_globaltype_mutability(gt1))
        self.assertTrue(wasm_globaltype_mutability(gt2))

        wasm_globaltype_delete(gt1)
        wasm_globaltype_delete(gt2)

    def test_wasm_globaltype_mutability_neg(self):
        self.assertFalse(
            wasm_globaltype_mutability(create_null_pointer(wasm_globaltype_t))
        )

    def test_wasm_globaltype_copy_pos(self):
        vt = wasm_valtype_new(WASM_I32)
        gt1 = wasm_globaltype_new(vt, True)
        gt2 = wasm_globaltype_copy(gt1)

        self.assertEqual(dereference(gt1), dereference(gt2))

        wasm_globaltype_delete(gt1)
        wasm_globaltype_delete(gt2)

    def test_wasm_globaltype_copy_neg(self):
        gt2 = wasm_globaltype_copy(create_null_pointer(wasm_globaltype_t))

        self.assertIsNullPointer(gt2)
        wasm_globaltype_delete(gt2)

    def test_wasm_limit_new(self):
        limit = wasm_limits_new(10, 20)
        self.assertIsNotNullPointer(limit)
        self.assertEqual(dereference(limit).min, 10)
        self.assertEqual(dereference(limit).max, 20)

    def test_wasm_tabletype_new_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        limit = wasm_limits_new(0, 0xFF)
        tt = wasm_tabletype_new(vt, limit)

        self.assertIsNotNullPointer(tt)
        wasm_tabletype_delete(tt)

    def test_wasm_tabletype_new_null_val_type(self):
        limit = wasm_limits_new(0, 0xFFFFFFFF)
        tt = wasm_tabletype_new(create_null_pointer(wasm_valtype_t), limit)

        self.assertIsNullPointer(tt)
        wasm_tabletype_delete(tt)

    def test_wasm_tabletype_new_null_limits(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        tt = wasm_tabletype_new(vt, create_null_pointer(wasm_limits_t))

        self.assertIsNullPointer(tt)
        wasm_tabletype_delete(tt)

    def test_wasm_tabletype_delete_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        limit = wasm_limits_new(0, 0xFFFFFFFF)
        tt = wasm_tabletype_new(vt, limit)
        wasm_tabletype_delete(tt)

    def test_wasm_tabletype_delete_neg(self):
        wasm_tabletype_delete(create_null_pointer(wasm_tabletype_t))

    def test_wasm_tabletype_element_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        limit = wasm_limits_new(0, 0xFFFFFFFF)
        tt = wasm_tabletype_new(vt, limit)
        vt_ret = wasm_tabletype_element(tt)

        self.assertEqual(dereference(vt), dereference(vt_ret))

        wasm_tabletype_delete(tt)

    def test_wasm_tabletype_element_neg(self):
        vt_ret = wasm_tabletype_element(create_null_pointer(wasm_tabletype_t))
        self.assertIsNullPointer(vt_ret)

    def test_wasm_tabletype_limits_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        limit = wasm_limits_new(100, 256)
        tt = wasm_tabletype_new(vt, limit)
        limit_ret = wasm_tabletype_limits(tt)

        self.assertEqual(dereference(limit), dereference(limit_ret))

        wasm_tabletype_delete(tt)

    def test_wasm_tabletype_limits_neg(self):
        limit_ret = wasm_tabletype_limits(create_null_pointer(wasm_tabletype_t))
        self.assertIsNullPointer(limit_ret)

    def test_wasm_tabletype_copy_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        limit = wasm_limits_new(13, 19)
        tt1 = wasm_tabletype_new(vt, limit)
        tt2 = wasm_tabletype_copy(tt1)

        self.assertEqual(dereference(tt1), dereference(tt2))

        wasm_tabletype_delete(tt1)
        wasm_tabletype_delete(tt2)

    def test_wasm_tabletype_copy_neg(self):
        tt2 = wasm_tabletype_copy(create_null_pointer(wasm_tabletype_t))
        self.assertIsNullPointer(tt2)
        wasm_tabletype_delete(tt2)

    def test_wasm_memorytype_new_pos(self):
        limit = wasm_limits_new(0, 3)
        mt = wasm_memorytype_new(limit)

        self.assertIsNotNullPointer(mt)

        wasm_memorytype_delete(mt)

    def test_wasm_memorytype_new_neg(self):
        mt = wasm_memorytype_new(None)

        self.assertIsNullPointer(mt)

        wasm_memorytype_delete(mt)

    def test_wasm_memorytype_delete_pos(self):
        limit = wasm_limits_new(1, 2)
        mt = wasm_memorytype_new(limit)
        wasm_memorytype_delete(mt)

    def test_wasm_memorytype_delete_neg(self):
        wasm_memorytype_delete(create_null_pointer(wasm_memorytype_t))

    def test_wasm_memorytype_limits_pos(self):
        limit = wasm_limits_new(3, 8)
        mt = wasm_memorytype_new(limit)
        limit_ret = wasm_memorytype_limits(mt)

        self.assertEqual(dereference(limit), dereference(limit_ret))

        wasm_memorytype_delete(mt)

    def test_wasm_memorytype_limits_neg(self):
        wasm_memorytype_limits(create_null_pointer(wasm_memorytype_t))

    def test_wasm_memorytype_copy_pos(self):
        limit = wasm_limits_new(7, 13)
        mt1 = wasm_memorytype_new(limit)
        mt2 = wasm_memorytype_copy(mt1)

        self.assertEqual(
            dereference(mt1),
            dereference(mt2),
        )

        wasm_memorytype_delete(mt1)
        wasm_memorytype_delete(mt2)

    def test_wasm_memorytype_copy_neg(self):
        mt2 = wasm_memorytype_copy(create_null_pointer(wasm_memorytype_t))

        self.assertIsNullPointer(mt2)

        wasm_memorytype_delete(mt2)

    def test_wasm_externtype_kind_pos(self):
        ft = wasm_functype_new_0_0()
        gt = wasm_globaltype_new(wasm_valtype_new(WASM_FUNCREF), True)
        mt = wasm_memorytype_new(wasm_limits_new(1, 2))
        tt = wasm_tabletype_new(wasm_valtype_new(WASM_FUNCREF), wasm_limits_new(10, 20))
        ets = [
            wasm_functype_as_externtype(ft),
            wasm_globaltype_as_externtype(gt),
            wasm_memorytype_as_externtype(mt),
            wasm_tabletype_as_externtype(tt),
        ]
        type_kinds = [wasm_externtype_kind(et) for et in ets]

        self.assertEqual(
            type_kinds,
            [
                WASM_EXTERN_FUNC,
                WASM_EXTERN_GLOBAL,
                WASM_EXTERN_MEMORY,
                WASM_EXTERN_TABLE,
            ],
        )

        [wasm_externtype_delete(et) for et in ets]

    def test_wasm_externtype_kind_neg(self):
        et = wasm_memorytype_as_externtype(create_null_pointer(wasm_memorytype_t))
        self.assertIsNullPointer(et)

    def test_wasm_externtype_delete_pos(self):
        mt = wasm_memorytype_new(wasm_limits_new(10, 20))
        et = wasm_memorytype_as_externtype(mt)
        wasm_externtype_delete(et)

    def test_wasm_externtype_delete_neg(self):
        et = wasm_globaltype_as_externtype(create_null_pointer(wasm_globaltype_t))
        wasm_externtype_delete(et)

    def test_wasm_externtype_copy_pos(self):
        tt1 = wasm_tabletype_new(
            wasm_valtype_new(WASM_FUNCREF), wasm_limits_new(10, 20)
        )
        et1 = wasm_tabletype_as_externtype(tt1)
        et2 = wasm_externtype_copy(et1)

        tt2 = wasm_externtype_as_tabletype(et2)
        self.assertEqual(dereference(tt1), dereference(tt2))

        wasm_externtype_delete(et2)
        wasm_externtype_delete(et1)

    def test_wasm_externtype_copy_neg(self):
        et1 = create_null_pointer(wasm_externtype_t)
        et2 = wasm_externtype_copy(et1)
        wasm_externtype_delete(et2)
        wasm_externtype_delete(et1)

    def test_wasm_name_new_from_string(self):
        s = "let the stars shine upon you"
        name = wasm_name_new_from_string(s)

        name_data = c.cast(name.data, c.c_char_p)
        name_data = bytes.decode(name_data.value)
        self.assertEqual(name_data, s)

    def test_wasm_importtype_new_pos(self):
        module_name = "mA"
        field_name = "func#1"
        module_name = wasm_name_new_from_string(module_name)
        field_name = wasm_name_new_from_string(field_name)
        ft = wasm_functype_new_0_0()
        et = wasm_functype_as_externtype(ft)
        it = wasm_importtype_new(module_name, field_name, et)

        self.assertIsNotNullPointer(it)
        self.assertEqual(dereference(wasm_importtype_module(it)), module_name)
        self.assertEqual(dereference(wasm_importtype_name(it)), field_name)
        self.assertEqual(dereference(wasm_importtype_type(it)), dereference(et))

        wasm_importtype_delete(it)

    def test_wasm_importtype_new_null_ext_type(self):
        module_name = "mA"
        field_name = "func#1"
        module_name = wasm_name_new_from_string(module_name)
        field_name = wasm_name_new_from_string(field_name)
        it = wasm_importtype_new(
            module_name,
            field_name,
            create_null_pointer(wasm_externtype_t),
        )

        self.assertIsNullPointer(it)

        wasm_importtype_delete(it)

    def test_wasm_importtype_new_null_module(self):
        field_name = "func#1"
        field_name = wasm_name_new_from_string(field_name)
        ft = wasm_functype_new_0_0()
        et = wasm_functype_as_externtype(ft)
        it = wasm_importtype_new(create_null_pointer(wasm_name_t), field_name, et)

        self.assertIsNullPointer(it)

        wasm_importtype_delete(it)

    def test_wasm_importtype_new_null_field(self):
        module_name = "mA"
        module_name = wasm_name_new_from_string(module_name)
        ft = wasm_functype_new_0_0()
        et = wasm_functype_as_externtype(ft)
        it = wasm_importtype_new(module_name, create_null_pointer(wasm_name_t), et)

        self.assertIsNullPointer(it)

        wasm_importtype_delete(it)

    def test_wasm_importtype_copy_pos(self):
        module_name = "mA"
        field_name = "memory#1"
        module_name = wasm_name_new_from_string(module_name)
        field_name = wasm_name_new_from_string(field_name)
        mt = wasm_memorytype_new(wasm_limits_new(10, 20))
        et = wasm_memorytype_as_externtype(mt)
        it1 = wasm_importtype_new(module_name, field_name, et)
        it2 = wasm_importtype_copy(it1)

        self.assertEqual(dereference(it1), dereference(it2))

        wasm_importtype_delete(it1)
        wasm_importtype_delete(it2)

    def test_wasm_importtype_copy_neg(self):
        it1 = create_null_pointer(wasm_importtype_t)
        it2 = wasm_importtype_copy(it1)
        wasm_importtype_delete(it1)
        wasm_importtype_delete(it2)

    def test_wasm_importtype_delete_pos(self):
        module_name = "mA"
        field_name = "memory#1"
        module_name = wasm_name_new_from_string(module_name)
        field_name = wasm_name_new_from_string(field_name)
        tt = wasm_tabletype_new(wasm_valtype_new(WASM_FUNCREF), wasm_limits_new(10, 20))
        et = wasm_tabletype_as_externtype(tt)
        it = wasm_importtype_new(module_name, field_name, et)
        wasm_importtype_delete(it)

    def test_wasm_importtype_delete_neg(self):
        wasm_importtype_delete(create_null_pointer(wasm_importtype_t))

    def test_wasm_importtype_module_pos(self):
        module_name = "mA"
        field_name = "func#1"
        module_name = wasm_name_new_from_string(module_name)
        field_name = wasm_name_new_from_string(field_name)
        ft = wasm_functype_new_0_0()
        et = wasm_functype_as_externtype(ft)
        it = wasm_importtype_new(module_name, field_name, et)
        module_name_ret = wasm_importtype_module(it)

        self.assertEqual(dereference(module_name_ret), module_name)

        wasm_importtype_delete(it)

    def test_wasm_importtype_module_neg(self):
        it = create_null_pointer(wasm_importtype_t)
        wasm_importtype_module(it)
        wasm_importtype_delete(it)

    def test_wasm_importtype_name_pos(self):
        module_name = "mA"
        field_name = "func#1"
        module_name = wasm_name_new_from_string(module_name)
        field_name = wasm_name_new_from_string(field_name)
        ft = wasm_functype_new_0_0()
        et = wasm_functype_as_externtype(ft)
        it = wasm_importtype_new(module_name, field_name, et)
        field_name_ret = wasm_importtype_name(it)

        self.assertEqual(dereference(field_name_ret), field_name)

        wasm_importtype_delete(it)

    def test_wasm_importtype_name_neg(self):
        it = create_null_pointer(wasm_importtype_t)
        wasm_importtype_name(it)
        wasm_importtype_delete(it)

    def test_wasm_importtype_type_pos(self):
        module_name = "mA"
        field_name = "func#1"
        module_name = wasm_name_new_from_string(module_name)
        field_name = wasm_name_new_from_string(field_name)
        ft = wasm_functype_new_0_0()
        et = wasm_functype_as_externtype(ft)
        it = wasm_importtype_new(module_name, field_name, et)
        et_ret = wasm_importtype_type(it)

        self.assertEqual(dereference(et_ret), dereference(et))

        wasm_importtype_delete(it)

    def test_wasm_importtype_type_neg(self):
        it = create_null_pointer(wasm_importtype_t)
        wasm_importtype_type(it)
        wasm_importtype_delete(it)

    def test_wasm_exporttype_new_pos(self):
        name = "hello"
        name = wasm_name_new_from_string(name)
        ft = wasm_functype_new_0_0()
        ft = wasm_functype_as_externtype(ft)
        et = wasm_exporttype_new(name, ft)

        self.assertIsNotNullPointer(et)

        wasm_exporttype_delete(et)

    def test_wasm_exporttype_new_null_name(self):
        name = create_null_pointer(wasm_name_t)
        ft = wasm_functype_new_0_0()
        ft = wasm_functype_as_externtype(ft)
        et = wasm_exporttype_new(name, ft)

        self.assertIsNullPointer(et)

        wasm_exporttype_delete(et)

    def test_wasm_exporttype_new_null_ext_type(self):
        name = "hello"
        name = wasm_name_new_from_string(name)
        ext_type = create_null_pointer(wasm_externtype_t)
        et = wasm_exporttype_new(name, ext_type)

        self.assertIsNullPointer(et)

        wasm_exporttype_delete(et)

    def test_wasm_exporttype_copy_pos(self):
        name = "hello"
        name = wasm_name_new_from_string(name)
        gt = wasm_globaltype_new(wasm_valtype_new(WASM_F32), True)
        gt = wasm_globaltype_as_externtype(gt)
        et1 = wasm_exporttype_new(name, gt)
        et2 = wasm_exporttype_copy(et1)

        self.assertEqual(
            dereference(et1),
            dereference(et2),
        )

        wasm_exporttype_delete(et1)
        wasm_exporttype_delete(et2)

    def test_wasm_exporttype_copy_neg(self):
        et1 = create_null_pointer(wasm_exporttype_t)
        et2 = wasm_exporttype_copy(et1)

        wasm_exporttype_delete(et1)
        wasm_exporttype_delete(et2)

    def test_wasm_exporttype_delete_pos(self):
        name = "hello"
        name = wasm_name_new_from_string(name)
        mt = wasm_memorytype_new(wasm_limits_new(10, 20))
        mt = wasm_memorytype_as_externtype(mt)
        et = wasm_exporttype_new(name, mt)

        wasm_exporttype_delete(et)

    def test_wasm_exporttype_delete_neg(self):
        et = create_null_pointer(wasm_exporttype_t)
        wasm_exporttype_delete(et)

    def test_wasm_exporttype_name_pos(self):
        name = "hello"
        name = wasm_name_new_from_string(name)
        tt = wasm_tabletype_new(wasm_valtype_new(WASM_FUNCREF), wasm_limits_new(10, 20))
        tt = wasm_tabletype_as_externtype(tt)
        et = wasm_exporttype_new(name, tt)
        name_ret = wasm_exporttype_name(et)

        self.assertEqual(dereference(name_ret), name)

        wasm_exporttype_delete(et)

    def test_wasm_exporttype_name_neg(self):
        et = create_null_pointer(wasm_exporttype_t)
        wasm_exporttype_name(et)
        wasm_exporttype_delete(et)

    def test_wasm_exporttype_type_pos(self):
        name = "hello"
        name = wasm_name_new_from_string(name)
        tt = wasm_tabletype_new(wasm_valtype_new(WASM_FUNCREF), wasm_limits_new(10, 20))
        tt = wasm_tabletype_as_externtype(tt)
        et = wasm_exporttype_new(name, tt)
        tt_ret = wasm_exporttype_type(et)

        self.assertEqual(dereference(tt_ret), dereference(tt))

        wasm_exporttype_delete(et)

    def test_wasm_exporttype_type_neg(self):
        et = create_null_pointer(wasm_exporttype_t)
        wasm_exporttype_type(et)
        wasm_exporttype_delete(et)

    def test_wasm_i32_val(self):
        val = wasm_i32_val(100)

        self.assertEqual(val.kind, WASM_I32)
        self.assertEqual(val.of.i32, 100)

        # can not use wasm_val_delete() because it is not malloced

    def test_wasm_i64_val(self):
        val = wasm_i64_val(-100)

        self.assertEqual(val.kind, WASM_I64)
        self.assertEqual(val.of.i64, -100)

        # can not use wasm_val_delete() because it is not malloced

    def test_wasm_f32_val(self):
        val = wasm_f32_val(100)

        self.assertEqual(val.kind, WASM_F32)
        self.assertEqual(val.of.f32, 100.0)

        # can not use wasm_val_delete() because it is not malloced

    def test_wasm_f64_val(self):
        val = wasm_f64_val(-100)

        self.assertEqual(val.kind, WASM_F64)
        self.assertEqual(val.of.f64, -100.0)

        # can not use wasm_val_delete() because it is not malloced

    # there is no wasm_val_new() to malloc a wasm_val_t
    def test_wasm_val_delete(self):
        pass

    def test_wasm_val_copy(self):
        v1 = wasm_f32_val(3.14)
        v2 = wasm_val_t()
        wasm_val_copy(v1, v2)

        self.assertEqual(v1, v2)
        # can not use wasm_val_delete() because it is not malloced

    def test_wasm_ref_delete_neg(self):
        ref = create_null_pointer(wasm_ref_t)
        wasm_ref_delete(ref)

        ref = wasm_ref_t()
        wasm_ref_delete(ref)

    def test_wasm_trap_new_pos(self):
        # can't create a trap with traces(wasm_frame_vec_t)
        msg = wasm_name_new_from_string("a fake trap")
        trap = wasm_trap_new(self._wasm_store, msg)

        self.assertIsNotNone(trap)

        wasm_trap_delete(trap)

    def test_wasm_trap_new_null_msg(self):
        trap = wasm_trap_new(self._wasm_store, create_null_pointer(wasm_name_t))

        self.assertIsNotNone(trap)
        self.assertIsNotNullPointer(trap)

        wasm_trap_delete(trap)

    def test_wasm_trap_message_pos(self):
        msg = wasm_name_new_from_string("a fake trap")
        trap = wasm_trap_new(self._wasm_store, msg)
        msg_in_trap = wasm_message_t()
        wasm_trap_message(trap, msg_in_trap)

        self.assertEqual(
            msg,
            msg_in_trap,
        )

        wasm_trap_delete(trap)

    def test_wasm_trap_message_null_trap(self):
        msg = wasm_name_new_from_string("a fake trap")
        wasm_trap_message(create_null_pointer(wasm_trap_t), msg)

    def test_wasm_trap_message_null_out(self):
        msg = wasm_name_new_from_string("a fake trap")
        trap = wasm_trap_new(self._wasm_store, msg)
        wasm_trap_message(trap, create_null_pointer(wasm_message_t))
        wasm_trap_delete(trap)

    # test those APIs in advance:
    # wasm_trap_origin
    # wasm_trap_trace
    # wasm_frame_delete
    # wasm_frame_copy
    # wasm_frame_module_offset
    # wasm_frame_instance
    # wasm_frame_func_index
    # wasm_frame_func_offset

    def test_wasm_foreign_new_pos(self):
        foreign = wasm_foreign_new(self._wasm_store)

        self.assertIsNotNone(foreign)
        self.assertIsNotNullPointer(foreign)

        wasm_foreign_delete(foreign)

    def test_wasm_foreign_new_neg(self):
        foreign = wasm_foreign_new(create_null_pointer(wasm_store_t))

        self.assertIsNotNone(foreign)
        self.assertIsNullPointer(foreign)

        wasm_foreign_delete(foreign)

    def test_wasm_foreign_delete_pos(self):
        foreign = wasm_foreign_new(self._wasm_store)
        wasm_foreign_delete(foreign)

    def test_wasm_foreign_delete_neg(self):
        wasm_foreign_delete(create_null_pointer(wasm_foreign_t))

    # wasm_egnine_new()/wasm_engine_delete()
    # wasm_store_new()/wasm_store_delete()
    # used in setUpClass() and tearDownClass

    def test_wasm_module_new_pos(self):
        binary = load_module_file(MODULE_BINARY)
        module = wasm_module_new(self._wasm_store, binary)

        self.assertIsNotNone(module)
        self.assertIsNotNullPointer(module)

        wasm_byte_vec_delete(binary)
        wasm_module_delete(module)

    def test_wasm_module_new_neg(self):
        module = wasm_module_new(self._wasm_store, create_null_pointer(wasm_byte_vec_t))

        self.assertIsNotNone(module)
        self.assertIsNullPointer(module)

        wasm_module_delete(module)

    def test_wasm_module_delete_pos(self):
        binary = load_module_file(MODULE_BINARY)
        module = wasm_module_new(self._wasm_store, binary)
        wasm_byte_vec_delete(binary)
        wasm_module_delete(module)

    def test_wasm_module_delete_neg(self):
        module = wasm_module_new(self._wasm_store, create_null_pointer(wasm_byte_vec_t))
        wasm_module_delete(module)

    def test_wasm_module_validate_pos(self):
        binary = load_module_file(MODULE_BINARY)
        validation = wasm_module_validate(self._wasm_store, binary)

        self.assertTrue(validation)

        wasm_byte_vec_delete(binary)

    def test_wasm_module_validate_neg(self):
        tmp = (1024).to_bytes(2, byteorder="big")
        binary = load_module_file(tmp)
        validation = wasm_module_validate(self._wasm_store, binary)

        self.assertFalse(validation)

        wasm_byte_vec_delete(binary)

    def test_wasm_module_imports_pos(self):
        binary = load_module_file(MODULE_BINARY)
        module = wasm_module_new(self._wasm_store, binary)
        imports = wasm_importtype_vec_t()
        wasm_module_imports(module, imports)

        imports_list = wasm_vec_to_list(imports)
        self.assertEqual(len(imports_list), 2)

        func_type = wasm_functype_new_1_1(
            wasm_valtype_new(WASM_F32),
            wasm_valtype_new(WASM_F64),
        )
        ext_type = wasm_functype_as_externtype(func_type)
        self.assertEqual(
            dereference(wasm_importtype_type(imports_list[0])), dereference(ext_type)
        )

        wasm_externtype_delete(ext_type)
        wasm_importtype_vec_delete(imports)
        wasm_byte_vec_delete(binary)
        wasm_module_delete(module)

    def test_wasm_module_imports_null_module(self):
        imports = wasm_importtype_vec_t()
        wasm_module_imports(create_null_pointer(wasm_module_t), imports)

        self.assertEqual(imports.size, 0)

        wasm_importtype_vec_delete(imports)

    def test_wasm_module_imports_null_out(self):
        binary = load_module_file(MODULE_BINARY)
        module = wasm_module_new(self._wasm_store, binary)
        wasm_module_imports(module, create_null_pointer(wasm_importtype_vec_t))
        wasm_byte_vec_delete(binary)
        wasm_module_delete(module)

    def test_wasm_module_exports_pos(self):
        binary = load_module_file(MODULE_BINARY)
        module = wasm_module_new(self._wasm_store, binary)
        exports = wasm_exporttype_vec_t()
        wasm_module_exports(module, exports)

        exports_list = wasm_vec_to_list(exports)
        self.assertEqual(len(exports_list), 2)

        glbl_type = wasm_globaltype_new(wasm_valtype_new(WASM_F32), True)
        ext_type = wasm_globaltype_as_externtype(glbl_type)
        self.assertEqual(
            dereference(wasm_exporttype_type(exports_list[1])), dereference(ext_type)
        )

        wasm_exporttype_vec_delete(exports)
        wasm_byte_vec_delete(binary)
        wasm_module_delete(module)

    def test_wasm_module_exports_null_module(self):
        exports = wasm_exporttype_vec_t()
        wasm_module_exports(create_null_pointer(wasm_module_t), exports)

        self.assertEqual(exports.size, 0)

        wasm_exporttype_vec_delete(exports)

    def test_wasm_module_exports_null_out(self):
        binary = load_module_file(MODULE_BINARY)
        module = wasm_module_new(self._wasm_store, binary)
        wasm_module_exports(module, create_null_pointer(wasm_exporttype_vec_t))
        wasm_byte_vec_delete(binary)
        wasm_module_delete(module)

    def test_wasm_instance_new_pos_empty_imports(self):
        binary = load_module_file(MODULE_BINARY)
        module = wasm_module_new(self._wasm_store, binary)
        imports = wasm_extern_vec_t()
        wasm_extern_vec_new_empty(imports)
        instance = wasm_instance_new(
            self._wasm_store, module, imports, create_null_pointer(wasm_trap_t)
        )

        wasm_module_delete(module)

        self.assertIsNullPointer(instance)

    def test_wasm_instance_new_pos(self):
        binary = load_module_file(MODULE_BINARY)
        module = wasm_module_new(self._wasm_store, binary)

        ft = wasm_functype_new_1_1(
            wasm_valtype_new(WASM_F32),
            wasm_valtype_new(WASM_F64),
        )
        func = wasm_func_new(self._wasm_store, ft, callback)

        gt = wasm_globaltype_new(wasm_valtype_new(WASM_I32), True)
        init = wasm_i32_val(100)
        gb = wasm_global_new(self._wasm_store, gt, init)

        imports = wasm_extern_vec_t()
        data = list_to_carray(
            c.POINTER(wasm_extern_t),
            wasm_func_as_extern(func),
            wasm_global_as_extern(gb),
        )
        wasm_extern_vec_new(imports, 2, data)

        instance = wasm_instance_new(
            self._wasm_store, module, imports, create_null_pointer(wasm_trap_t)
        )

        self.assertIsNotNone(instance)

        wasm_instance_delete(instance)
        wasm_module_delete(module)

    def test_wasm_instance_new_neg_null_imports(self):
        binary = load_module_file(MODULE_BINARY)
        module = wasm_module_new(self._wasm_store, binary)
        instance = wasm_instance_new(
            self._wasm_store,
            module,
            create_null_pointer(wasm_extern_vec_t),
            create_null_pointer(wasm_trap_t),
        )

        wasm_module_delete(module)

        self.assertIsNullPointer(instance)

    # test those APIs in advanced:
    # wasm_instance_delete
    # wasm_instance_exports

    def test_wasm_func_new_pos(self):
        vt1 = wasm_valtype_new(WASM_F32)
        vt2 = wasm_valtype_new(WASM_FUNCREF)
        ft = wasm_functype_new_1_1(vt1, vt2)
        func = wasm_func_new(self._wasm_store, ft, callback)

        self.assertIsNotNone(func)
        self.assertIsNotNullPointer(func)

        wasm_func_delete(func)

    def test_wasm_func_new_null_type(self):
        func = wasm_func_new(
            self._wasm_store, create_null_pointer(wasm_functype_t), callback
        )

        self.assertIsNotNone(func)
        self.assertIsNullPointer(func)

        wasm_func_delete(func)

    def test_wasm_func_new_null_callback(self):
        vt1 = wasm_valtype_new(WASM_F32)
        vt2 = wasm_valtype_new(WASM_FUNCREF)
        ft = wasm_functype_new_1_1(vt1, vt2)
        func = wasm_func_new(self._wasm_store, ft, wasm_func_callback_t())

        self.assertIsNotNone(func)
        self.assertIsNullPointer(func)

        wasm_func_delete(func)

    def test_wasm_func_new_with_env_pos(self):
        ft = wasm_functype_new_3_1(
            wasm_valtype_new(WASM_I32),
            wasm_valtype_new(WASM_F32),
            wasm_valtype_new(WASM_I64),
            wasm_valtype_new(WASM_I64),
        )
        func = wasm_func_new_with_env(
            self._wasm_store,
            ft,
            callback_with_env,
            c.c_void_p(0),
            wasm_finalizer(0),
        )

        self.assertIsNotNone(func)
        self.assertIsNotNullPointer(func)

        wasm_func_delete(func)

    def test_wasm_func_new_with_env_null_type(self):
        func = wasm_func_new_with_env(
            self._wasm_store,
            create_null_pointer(wasm_functype_t),
            callback_with_env,
            c.c_void_p(0),
            wasm_finalizer(0),
        )

        self.assertIsNotNone(func)
        self.assertIsNullPointer(func)

        wasm_func_delete(func)

    def test_wasm_func_new_with_env_null_callback(self):
        ft = wasm_functype_new_3_1(
            wasm_valtype_new(WASM_I32),
            wasm_valtype_new(WASM_F32),
            wasm_valtype_new(WASM_I64),
            wasm_valtype_new(WASM_I64),
        )
        func = wasm_func_new_with_env(
            self._wasm_store,
            ft,
            wasm_func_callback_with_env_t(),
            c.c_void_p(0),
            wasm_finalizer(0),
        )

        self.assertIsNotNone(func)
        self.assertIsNullPointer(func)

        wasm_func_delete(func)

    def test_wasm_func_delete_pos(self):
        ft = wasm_functype_new_0_0()
        func = wasm_func_new(self._wasm_store, ft, callback)
        wasm_func_delete(func)

    def test_wasm_func_delete_neg(self):
        wasm_func_delete(create_null_pointer(wasm_func_t))

    def test_wasm_func_type_pos(self):
        ft = wasm_functype_new_2_0(
            wasm_valtype_new(WASM_F32),
            wasm_valtype_new(WASM_FUNCREF),
        )
        func = wasm_func_new(self._wasm_store, ft, callback)
        ft_ret = wasm_func_type(func)

        self.assertEqual(
            dereference(ft),
            dereference(ft_ret),
        )

        wasm_functype_delete(ft_ret)
        wasm_func_delete(func)

    def test_wasm_func_type_neg(self):
        ft_ret = wasm_func_type(create_null_pointer(wasm_func_t))
        wasm_functype_delete(ft_ret)

    def test_wasm_func_copy_pos(self):
        vt1 = wasm_valtype_new(WASM_F32)
        ft = wasm_functype_new_0_1(vt1)
        func1 = wasm_func_new(self._wasm_store, ft, callback)
        func2 = wasm_func_copy(func1)

        self.assertEqual(
            dereference(wasm_func_type(func1)), dereference(wasm_func_type(func2))
        )

        wasm_func_delete(func2)
        wasm_func_delete(func1)

    def test_wasm_func_copy_neg(self):
        func1 = wasm_func_new(
            self._wasm_store, create_null_pointer(wasm_functype_t), callback
        )
        func2 = wasm_func_copy(func1)

        wasm_func_delete(func2)
        wasm_func_delete(func1)

    # test wasm_func_call in advanced

    def test_wasm_global_new_pos(self):
        vt = wasm_valtype_new(WASM_F32)
        gt = wasm_globaltype_new(vt, False)
        v = wasm_f32_val(3.14)
        g = wasm_global_new(self._wasm_store, gt, v)

        self.assertIsNotNone(g)
        self.assertIsNotNullPointer(g)

        wasm_globaltype_delete(gt)
        wasm_global_delete(g)

    def test_wasm_global_new_null_type(self):
        v = wasm_f32_val(3.14)
        g = wasm_global_new(self._wasm_store, create_null_pointer(wasm_globaltype_t), v)

        self.assertIsNotNone(g)
        self.assertIsNullPointer(g)

        wasm_global_delete(g)

    def test_wasm_global_new_null_init(self):
        vt = wasm_valtype_new(WASM_F32)
        gt = wasm_globaltype_new(vt, False)
        g = wasm_global_new(self._wasm_store, gt, create_null_pointer(wasm_val_t))

        self.assertIsNotNone(g)
        self.assertIsNullPointer(g)

        wasm_globaltype_delete(gt)
        wasm_global_delete(g)

    def test_wasm_global_delete_pos(self):
        vt = wasm_valtype_new(WASM_I32)
        gt = wasm_globaltype_new(vt, True)
        v = wasm_i32_val(3)
        g = wasm_global_new(self._wasm_store, gt, v)
        wasm_globaltype_delete(gt)
        wasm_global_delete(g)

    def test_wasm_global_delete_neg(self):
        wasm_global_delete(create_null_pointer(wasm_global_t))

    def test_wasm_global_type_pos(self):
        vt = wasm_valtype_new(WASM_I64)
        gt = wasm_globaltype_new(vt, False)
        v = wasm_i32_val(3)
        g = wasm_global_new(self._wasm_store, gt, v)
        gt_ret = wasm_global_type(g)

        self.assertEqual(dereference(gt), dereference(gt_ret))

        wasm_globaltype_delete(gt)
        wasm_globaltype_delete(gt_ret)
        wasm_global_delete(g)

    def test_wasm_global_type_neg(self):
        gt = wasm_global_type(create_null_pointer(wasm_global_t))
        wasm_globaltype_delete(gt)

    # test wasm_global_get and wasm_global_set in advanced

    def test_wasm_table_new_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        limits = wasm_limits_new(10, 15)
        tt = wasm_tabletype_new(vt, limits)
        t = wasm_table_new(self._wasm_store, tt, create_null_pointer(wasm_ref_t))

        self.assertIsNotNone(t)
        self.assertIsNotNullPointer(t)

        wasm_table_delete(t)

    def test_wasm_table_new_null_type(self):
        t = wasm_table_new(
            self._wasm_store,
            create_null_pointer(wasm_tabletype_t),
            create_null_pointer(wasm_ref_t),
        )

        self.assertIsNotNone(t)
        self.assertIsNullPointer(t)

        wasm_table_delete(t)

    def test_wasm_table_delete_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        limits = wasm_limits_new(10, 15)
        tt = wasm_tabletype_new(vt, limits)
        t = wasm_table_new(self._wasm_store, tt, create_null_pointer(wasm_ref_t))
        wasm_table_delete(t)

    def test_wasm_table_delete_neg(self):
        wasm_table_delete(create_null_pointer(wasm_table_t))

    def test_wasm_table_type_pos(self):
        vt = wasm_valtype_new(WASM_FUNCREF)
        limits = wasm_limits_new(1, 2)
        tt = wasm_tabletype_new(vt, limits)
        t = wasm_table_new(self._wasm_store, tt, create_null_pointer(wasm_ref_t))
        tt_ret = wasm_table_type(t)

        self.assertEqual(
            dereference(tt),
            dereference(tt_ret),
        )

        wasm_table_delete(t)

    def test_wasm_table_type_neg(self):
        t = wasm_table_new(
            self._wasm_store,
            create_null_pointer(wasm_tabletype_t),
            create_null_pointer(wasm_ref_t),
        )
        tt_ret = wasm_table_type(t)
        wasm_table_delete(t)

    # test wasm_table_size, wasm_table_get, wasm_table_set in advanced

    def test_wasm_memory_new_pos(self):
        limits = wasm_limits_new(10, 12)
        mt = wasm_memorytype_new(limits)
        m = wasm_memory_new(self._wasm_store, mt)

        self.assertIsNotNullPointer(m)

        wasm_memory_delete(m)

    def test_wasm_memory_new_null_type(self):
        m = wasm_memory_new(self._wasm_store, create_null_pointer(wasm_memorytype_t))

        self.assertIsNullPointer(m)

        wasm_memory_delete(m)

    def test_wasm_memory_delete_pos(self):
        limits = wasm_limits_new(10, 21)
        mt = wasm_memorytype_new(limits)
        m = wasm_memory_new(self._wasm_store, mt)
        wasm_memory_delete(m)

    def test_wasm_memory_delete_neg(self):
        wasm_memory_delete(create_null_pointer(wasm_memory_t))

    def test_wasm_memory_type_pos(self):
        limits = wasm_limits_new(10, 21)
        mt = wasm_memorytype_new(limits)
        m = wasm_memory_new(self._wasm_store, mt)
        mt_ret = wasm_memory_type(m)

        self.assertEqual(dereference(mt), dereference(mt_ret))

        wasm_memory_delete(m)

    def test_wasm_memory_type_neg(self):
        mt = wasm_memory_type(create_null_pointer(wasm_memory_t))

        self.assertIsNullPointer(mt)
        wasm_memorytype_delete(mt)

    # test wasm_memory_size, wasm_memory_data, wasm_memory_data_size in advanced

    def test_wasm_extern_delete_pos(self):
        vt = wasm_valtype_new(WASM_I64)
        gt = wasm_globaltype_new(vt, False)
        v = wasm_i64_val(128)
        glb = wasm_global_new(self._wasm_store, gt, v)
        etrn = wasm_global_as_extern(glb)
        wasm_extern_delete(etrn)

    def test_wasm_extern_delete_neg(self):
        etrn = wasm_global_as_extern(create_null_pointer(wasm_global_t))
        wasm_extern_delete(etrn)

    def test_wasm_extern_type_pos(self):
        vt = wasm_valtype_new(WASM_I64)
        gt = wasm_globaltype_new(vt, False)
        v = wasm_i64_val(128)
        glb = wasm_global_new(self._wasm_store, gt, v)
        etrn = wasm_global_as_extern(glb)

        tp = wasm_extern_type(etrn)
        gt_ret = wasm_externtype_as_globaltype(tp)
        self.assertEqual(
            dereference(gt),
            dereference(gt_ret),
        )
        wasm_extern_delete(etrn)

    def test_wasm_extern_type_neg(self):
        wasm_extern_type(create_null_pointer(wasm_extern_t))

    def test_wasm_extern_kind_pos(self):
        ft = wasm_functype_new_0_0()
        func = wasm_func_new(self._wasm_store, ft, callback)
        etrn = wasm_func_as_extern(func)
        kind = wasm_extern_kind(etrn)

        self.assertEqual(WASM_EXTERN_FUNC, kind)

        wasm_extern_delete(etrn)

    def test_wasm_extern_kind_neg(self):
        wasm_extern_kind(create_null_pointer(wasm_extern_t))

    @classmethod
    def tearDownClass(cls):
        wasm_store_delete(cls._wasm_store)
        wasm_engine_delete(cls._wasm_engine)


if __name__ == "__main__":
    unittest.main()
