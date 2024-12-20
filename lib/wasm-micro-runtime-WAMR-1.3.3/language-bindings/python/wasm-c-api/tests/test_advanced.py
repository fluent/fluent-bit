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
import math
import unittest

import wamr.wasmcapi.ffi as ffi


# It is a module likes:
# (module
#   (import "mod" "g0" (global i32))
#   (import "mod" "f0" (func (param f32) (result f64)))
#
#   (func (export "f1") (param i32 i64))
#   (global (export "g1") (mut f32) (f32.const 3.14))
#   (memory (export "m1") 1 2)
#   (table (export "t1") 1 funcref)
#
#   (func (export "f2") (unreachable))
# )
MODULE_BINARY = (
    b"\x00asm\x01\x00\x00\x00\x01\x0e\x03`\x01}\x01|`\x02\x7f~\x00`\x00"
    b"\x00\x02\x14\x02\x03mod\x02g0\x03\x7f\x00\x03mod\x02f0\x00\x00\x03\x03"
    b"\x02\x01\x02\x04\x04\x01p\x00\x01\x05\x04\x01\x01\x01\x02\x06\t\x01}\x01C"
    b"\xc3\xf5H@\x0b\x07\x1a\x05\x02f1\x00\x01\x02g1\x03\x01\x02m1\x02\x00\x02t1"
    b"\x01\x00\x02f2\x00\x02\n\x08\x02\x02\x00\x0b\x03\x00\x00\x0b"
)

# False -> True when testing with a library enabling WAMR_BUILD_DUMP_CALL_STACK flag
TEST_WITH_WAMR_BUILD_DUMP_CALL_STACK = False


@ffi.wasm_func_cb_decl
def callback(args, results):
    args = ffi.dereference(args)
    results = ffi.dereference(results)

    arg_v = args.data[0]

    result_v = ffi.wasm_f64_val(arg_v.of.f32 * 2.0)
    ffi.wasm_val_copy(results.data[0], result_v)
    results.num_elems = 1

    print(f"\nIn callback: {arg_v} --> {result_v}\n")


@ffi.wasm_func_with_env_cb_decl
def callback_with_env(env, args, results):
    # pylint: disable=unused-argument
    print("summer")


class AdvancedTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("Initializing...")
        cls._wasm_engine = ffi.wasm_engine_new()
        cls._wasm_store = ffi.wasm_store_new(cls._wasm_engine)

    def assertIsNullPointer(self, pointer):
        # pylint: disable=invalid-name
        if not ffi.is_null_pointer(pointer):
            self.fail("not a non-null pointer")

    def assertIsNotNullPointer(self, pointer):
        # pylint: disable=invalid-name
        if ffi.is_null_pointer(pointer):
            self.fail("not a non-null pointer")

    def load_binary(self, binary_string):
        print("Load binary...")
        binary = ffi.load_module_file(binary_string)
        binary = c.pointer(binary)
        self.assertIsNotNullPointer(binary)
        return binary

    def compile(self, binary):
        print("Compile...")
        module = ffi.wasm_module_new(self._wasm_store, binary)
        self.assertIsNotNullPointer(module)
        return module

    def prepare_imports_local(self):
        print("Prepare imports...")
        func_type = ffi.wasm_functype_new_1_1(
            ffi.wasm_valtype_new(ffi.WASM_F32),
            ffi.wasm_valtype_new(ffi.WASM_F64),
        )
        func = ffi.wasm_func_new(self._wasm_store, func_type, callback)
        self.assertIsNotNullPointer(func)
        ffi.wasm_functype_delete(func_type)

        glbl_type = ffi.wasm_globaltype_new(ffi.wasm_valtype_new(ffi.WASM_I32), True)
        init = ffi.wasm_i32_val(1024)
        glbl = ffi.wasm_global_new(self._wasm_store, glbl_type, init)
        self.assertIsNotNullPointer(glbl)
        ffi.wasm_globaltype_delete(glbl_type)

        imports = ffi.wasm_extern_vec_t()
        data = ffi.list_to_carray(
            c.POINTER(ffi.wasm_extern_t),
            ffi.wasm_func_as_extern(func),
            ffi.wasm_global_as_extern(glbl),
        )
        ffi.wasm_extern_vec_new(imports, 2, data)
        imports = c.pointer(imports)
        self.assertIsNotNullPointer(imports)
        return imports

    def instantiate(self, module, imports):
        print("Instantiate module...")
        instance = ffi.wasm_instance_new(
            self._wasm_store, module, imports, ffi.create_null_pointer(ffi.wasm_trap_t)
        )
        self.assertIsNotNone(instance)
        self.assertIsNotNullPointer(instance)
        return instance

    def extract_exports(self, instance):
        print("Extracting exports...")
        exports = ffi.wasm_extern_vec_t()
        ffi.wasm_instance_exports(instance, exports)
        exports = c.pointer(exports)
        self.assertIsNotNullPointer(exports)
        return exports

    def setUp(self):
        binary = self.load_binary(MODULE_BINARY)
        self.module = self.compile(binary)
        self.imports = self.prepare_imports_local()
        self.instance = self.instantiate(self.module, self.imports)
        self.exports = self.extract_exports(self.instance)

        ffi.wasm_byte_vec_delete(binary)

    def tearDown(self):
        if self.imports:
            ffi.wasm_extern_vec_delete(self.imports)

        if self.exports:
            ffi.wasm_extern_vec_delete(self.exports)

        ffi.wasm_instance_delete(self.instance)
        ffi.wasm_module_delete(self.module)

    def test_wasm_func_call_wasm(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        print(export_list)

        func = ffi.wasm_extern_as_func(export_list[0])
        self.assertIsNotNullPointer(func)

        # make a call
        params = ffi.wasm_val_vec_t()
        data = ffi.list_to_carray(
            ffi.wasm_val_t,
            ffi.wasm_i32_val(1024),
            ffi.wasm_i64_val(1024 * 1024),
        )
        ffi.wasm_val_vec_new(params, 2, data)

        results = ffi.wasm_val_vec_t()
        ffi.wasm_val_vec_new_empty(results)

        ffi.wasm_func_call(func, params, results)

    def test_wasm_func_call_native(self):
        import_list = ffi.wasm_vec_to_list(self.imports)

        func = ffi.wasm_extern_as_func(import_list[0])
        self.assertIsNotNullPointer(func)

        params = ffi.wasm_val_vec_t()
        ffi.wasm_val_vec_new(
            params, 1, ffi.list_to_carray(ffi.wasm_val_t, ffi.wasm_f32_val(3.14))
        )
        results = ffi.wasm_val_vec_t()
        ffi.wasm_val_vec_new_uninitialized(results, 1)
        ffi.wasm_func_call(func, params, results)
        self.assertEqual(params.data[0].of.f32 * 2, results.data[0].of.f64)

    def test_wasm_func_call_unlinked(self):
        ft = ffi.wasm_functype_new_0_0()
        func = ffi.wasm_func_new(self._wasm_store, ft, callback)
        params = ffi.wasm_val_vec_t()
        ffi.wasm_val_vec_new_empty(params)
        results = ffi.wasm_val_vec_t()
        ffi.wasm_val_vec_new_empty(results)
        trap = ffi.wasm_func_call(func, params, results)
        ffi.wasm_func_delete(func)

    def test_wasm_global_get_wasm(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        glb = ffi.wasm_extern_as_global(export_list[1])
        self.assertIsNotNullPointer(glb)

        # access the global
        val = ffi.wasm_val_t()
        ffi.wasm_global_get(glb, val)
        self.assertAlmostEqual(val.of.f32, 3.14, places=3)

    def test_wasm_global_get_native(self):
        import_list = ffi.wasm_vec_to_list(self.imports)

        glb = ffi.wasm_extern_as_global(import_list[1])
        self.assertIsNotNullPointer(glb)

        val = ffi.wasm_val_t()
        ffi.wasm_global_get(glb, val)
        self.assertEqual(val.of.i32, 1024)

    def test_wasm_global_get_unlinked(self):
        gt = ffi.wasm_globaltype_new(ffi.wasm_valtype_new(ffi.WASM_I32), True)
        init = ffi.wasm_i32_val(32)
        glbl = ffi.wasm_global_new(self._wasm_store, gt, init)
        val_ret = ffi.wasm_f32_val(3.14)
        ffi.wasm_global_get(glbl, val_ret)
        ffi.wasm_global_delete(glbl)

        # val_ret wasn't touched, keep the original value
        self.assertAlmostEqual(val_ret.of.f32, 3.14, 3)

    def test_wasm_global_get_null_val(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        glb = ffi.wasm_extern_as_global(export_list[1])
        ffi.wasm_global_get(glb, ffi.create_null_pointer(ffi.wasm_val_t))

    def test_wasm_global_get_null_global(self):
        val = ffi.wasm_val_t()
        ffi.wasm_global_get(ffi.create_null_pointer(ffi.wasm_global_t), val)

    def test_wasm_global_set_wasm(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        glb = ffi.wasm_extern_as_global(export_list[1])
        self.assertIsNotNullPointer(glb)

        # access the global
        new_val = ffi.wasm_f32_val(math.e)
        ffi.wasm_global_set(glb, new_val)

        val = ffi.wasm_val_t()
        ffi.wasm_global_get(glb, val)
        self.assertNotEqual(val.of.f32, 3.14)

    def test_wasm_global_set_native(self):
        import_list = ffi.wasm_vec_to_list(self.imports)

        glb = ffi.wasm_extern_as_global(import_list[1])
        self.assertIsNotNullPointer(glb)

        new_val = ffi.wasm_i32_val(2048)
        ffi.wasm_global_set(glb, new_val)

        val = ffi.wasm_val_t()
        ffi.wasm_global_get(glb, val)
        self.assertEqual(val, new_val)

    def test_wasm_global_set_unlinked(self):
        gt = ffi.wasm_globaltype_new(ffi.wasm_valtype_new(ffi.WASM_I32), True)
        init = ffi.wasm_i32_val(32)
        glbl = ffi.wasm_global_new(self._wasm_store, gt, init)
        val_ret = ffi.wasm_f32_val(3.14)
        ffi.wasm_global_set(glbl, val_ret)
        ffi.wasm_global_delete(glbl)

    def test_wasm_global_set_null_v(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        glb = ffi.wasm_extern_as_global(export_list[1])
        # access the global
        ffi.wasm_global_set(glb, ffi.create_null_pointer(ffi.wasm_val_t))

    def test_wasm_global_set_null_global(self):
        # access the global
        new_val = ffi.wasm_f32_val(math.e)
        ffi.wasm_global_set(ffi.create_null_pointer(ffi.wasm_global_t), new_val)

    def test_wasm_table_size(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        tbl = ffi.wasm_extern_as_table(export_list[3])
        self.assertIsNotNullPointer(tbl)

        tbl_sz = ffi.wasm_table_size(tbl)
        self.assertEqual(tbl_sz, 1)

    def test_wasm_table_size_unlink(self):
        vt = ffi.wasm_valtype_new(ffi.WASM_FUNCREF)
        limits = ffi.wasm_limits_new(10, 15)
        tt = ffi.wasm_tabletype_new(vt, limits)
        tbl = ffi.wasm_table_new(
            self._wasm_store, tt, ffi.create_null_pointer(ffi.wasm_ref_t)
        )
        tbl_sz = ffi.wasm_table_size(tbl)
        ffi.wasm_table_delete(tbl)

    def test_wasm_table_size_null_table(self):
        ffi.wasm_table_size(ffi.create_null_pointer(ffi.wasm_table_t))

    def test_wasm_table_get(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        tbl = ffi.wasm_extern_as_table(export_list[3])
        self.assertIsNotNullPointer(tbl)

        ref = ffi.wasm_table_get(tbl, 0)
        self.assertIsNullPointer(ref)

        ref = ffi.wasm_table_get(tbl, 4096)
        self.assertIsNullPointer(ref)

    def test_wasm_table_get_unlinked(self):
        vt = ffi.wasm_valtype_new(ffi.WASM_FUNCREF)
        limits = ffi.wasm_limits_new(10, 15)
        tt = ffi.wasm_tabletype_new(vt, limits)
        tbl = ffi.wasm_table_new(
            self._wasm_store, tt, ffi.create_null_pointer(ffi.wasm_ref_t)
        )
        ffi.wasm_table_get(tbl, 0)
        ffi.wasm_table_delete(tbl)

    def test_wasm_table_get_null_table(self):
        ffi.wasm_table_get(ffi.create_null_pointer(ffi.wasm_table_t), 0)

    def test_wasm_table_get_out_of_bounds(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        tbl = ffi.wasm_extern_as_table(export_list[3])
        ffi.wasm_table_get(tbl, 1_000_000_000)

    def test_wasm_ref(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        func = ffi.wasm_extern_as_func(export_list[0])
        self.assertIsNotNullPointer(func)

        ref = ffi.wasm_func_as_ref(func)
        self.assertIsNotNullPointer(ref)

        func_from_ref = ffi.wasm_ref_as_func(ref)
        self.assertEqual(
            ffi.dereference(ffi.wasm_func_type(func)),
            ffi.dereference(ffi.wasm_func_type(func_from_ref)),
        )

    def test_wasm_table_set(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        tbl = ffi.wasm_extern_as_table(export_list[3])
        self.assertIsNotNullPointer(tbl)

        func = ffi.wasm_extern_as_func(export_list[0])
        ref = ffi.wasm_func_as_ref(func)

        ffi.wasm_table_set(tbl, 0, ref)

        ref_ret = ffi.wasm_table_get(tbl, 0)
        self.assertIsNotNullPointer(ref_ret)
        func_ret = ffi.wasm_ref_as_func(ref_ret)
        self.assertEqual(
            ffi.dereference(ffi.wasm_func_type(func)),
            ffi.dereference(ffi.wasm_func_type(func_ret)),
        )

    def test_wasm_table_set_unlinked(self):
        vt = ffi.wasm_valtype_new(ffi.WASM_FUNCREF)
        limits = ffi.wasm_limits_new(10, 15)
        tt = ffi.wasm_tabletype_new(vt, limits)
        tbl = ffi.wasm_table_new(
            self._wasm_store, tt, ffi.create_null_pointer(ffi.wasm_ref_t)
        )
        export_list = ffi.wasm_vec_to_list(self.exports)
        func = ffi.wasm_extern_as_func(export_list[0])
        ref = ffi.wasm_func_as_ref(func)
        ffi.wasm_table_set(tbl, 0, ref)
        ffi.wasm_table_delete(tbl)

    def test_wasm_table_set_null_table(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        func = ffi.wasm_extern_as_func(export_list[0])
        ref = ffi.wasm_func_as_ref(func)
        ffi.wasm_table_set(ffi.create_null_pointer(ffi.wasm_table_t), 0, ref)

    def test_wasm_table_set_null_ref(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        tbl = ffi.wasm_extern_as_table(export_list[3])
        ffi.wasm_table_set(tbl, 0, ffi.create_null_pointer(ffi.wasm_ref_t))

    def test_wasm_table_set_out_of_bounds(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        tbl = ffi.wasm_extern_as_table(export_list[3])
        func = ffi.wasm_extern_as_func(export_list[0])
        ref = ffi.wasm_func_as_ref(func)
        ffi.wasm_table_set(tbl, 1_000_000_000, ref)

    def test_wasm_memory_size(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        mem = ffi.wasm_extern_as_memory(export_list[2])
        self.assertIsNotNullPointer(mem)

        pg_sz = ffi.wasm_memory_size(mem)
        self.assertEqual(pg_sz, 1)

    def test_wasm_memory_size_unlinked(self):
        limits = ffi.wasm_limits_new(10, 12)
        mt = ffi.wasm_memorytype_new(limits)
        mem = ffi.wasm_memory_new(self._wasm_store, mt)
        ffi.wasm_memory_size(mem)
        ffi.wasm_memory_delete(mem)

    def test_wasm_memory_data(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        mem = ffi.wasm_extern_as_memory(export_list[2])
        self.assertIsNotNullPointer(mem)

        data_base = ffi.wasm_memory_data(mem)
        self.assertIsNotNone(data_base)

    def test_wasm_memory_data_unlinked(self):
        limits = ffi.wasm_limits_new(10, 12)
        mt = ffi.wasm_memorytype_new(limits)
        mem = ffi.wasm_memory_new(self._wasm_store, mt)
        ffi.wasm_memory_data(mem)
        ffi.wasm_memory_delete(mem)

    def test_wasm_memory_data_size(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        mem = ffi.wasm_extern_as_memory(export_list[2])
        self.assertIsNotNullPointer(mem)

        mem_sz = ffi.wasm_memory_data_size(mem)
        self.assertGreater(mem_sz, 0)

    def test_wasm_memory_data_size_unlinked(self):
        limits = ffi.wasm_limits_new(10, 12)
        mt = ffi.wasm_memorytype_new(limits)
        mem = ffi.wasm_memory_new(self._wasm_store, mt)
        ffi.wasm_memory_data_size(mem)
        ffi.wasm_memory_delete(mem)

    @unittest.skipUnless(
        TEST_WITH_WAMR_BUILD_DUMP_CALL_STACK,
        "need to enable WAMR_BUILD_DUMP_CALL_STACK",
    )
    # assertions only works if enabling WAMR_BUILD_DUMP_CALL_STACK
    def test_wasm_frame(self):
        export_list = ffi.wasm_vec_to_list(self.exports)
        func = ffi.wasm_extern_as_func(export_list[4])
        # make a call
        params = ffi.wasm_val_vec_t()
        ffi.wasm_val_vec_new_empty(params)
        results = ffi.wasm_val_vec_t()
        ffi.wasm_val_vec_new_empty(results)

        print("Making a call...")
        trap = ffi.wasm_func_call(func, params, results)

        message = ffi.wasm_message_t()
        ffi.wasm_trap_message(trap, message)
        self.assertIsNotNullPointer(c.pointer(message))
        print(message)

        frame = ffi.wasm_trap_origin(trap)
        self.assertIsNotNullPointer(frame)
        print(ffi.dereference(frame))

        traces = ffi.wasm_frame_vec_t()
        ffi.wasm_trap_trace(trap, traces)
        self.assertIsNotNullPointer(c.pointer(frame))

        instance = ffi.wasm_frame_instance(frame)
        self.assertIsNotNullPointer(instance)

        module_offset = ffi.wasm_frame_module_offset(frame)

        func_index = ffi.wasm_frame_func_index(frame)
        self.assertEqual(func_index, 2)

        func_offset = ffi.wasm_frame_func_offset(frame)
        self.assertGreater(func_offset, 0)

    @classmethod
    def tearDownClass(cls):
        print("Shutting down...")
        ffi.wasm_store_delete(cls._wasm_store)
        ffi.wasm_engine_delete(cls._wasm_engine)


if __name__ == "__main__":
    unittest.main()
