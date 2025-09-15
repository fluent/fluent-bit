# -*- coding: utf-8 -*-
#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=missing-module-docstring

"""
- Need to run *download_wamr.py* firstly.
- Parse *./wasm-micro-runtime/core/iwasm/include/wasm_c_api.h* and generate
  *wamr/binding.py*
"""
import os
import pathlib
import shutil
import sys

from pycparser import c_ast, parse_file

WASM_C_API_HEADER = "core/iwasm/include/wasm_c_api.h"
BINDING_PATH = "language-bindings/python/wamr/wasmcapi/binding.py"
# 4 spaces as default indent
INDENT = "    "

IGNORE_SYMOLS = (
    "wasm_engine_new_with_args",
    "wasm_valkind_is_num",
    "wasm_valkind_is_ref",
    "wasm_valtype_is_num",
    "wasm_valtype_is_ref",
    "wasm_valtype_new_i32",
    "wasm_valtype_new_i64",
    "wasm_valtype_new_f32",
    "wasm_valtype_new_f64",
    "wasm_valtype_new_anyref",
    "wasm_valtype_new_funcref",
    "wasm_functype_new_0_0",
    "wasm_functype_new_0_0",
    "wasm_functype_new_1_0",
    "wasm_functype_new_2_0",
    "wasm_functype_new_3_0",
    "wasm_functype_new_0_1",
    "wasm_functype_new_1_1",
    "wasm_functype_new_2_1",
    "wasm_functype_new_3_1",
    "wasm_functype_new_0_2",
    "wasm_functype_new_1_2",
    "wasm_functype_new_2_2",
    "wasm_functype_new_3_2",
    "wasm_val_init_ptr",
    "wasm_val_ptr",
    "wasm_val_t",
    "wasm_ref_t",
    "wasm_name_new_from_string",
    "wasm_name_new_from_string_nt",
)


class Visitor(c_ast.NodeVisitor):
    def __init__(self):
        self.type_map = {
            "_Bool": "c_bool",
            "byte_t": "c_ubyte",
            "char": "c_char",
            "errno_t": "c_int",
            "int": "c_int",
            "long": "c_long",
            "size_t": "c_size_t",
            "uint32_t": "c_uint32",
            "uint8_t": "c_uint8",
            "void": "None",
        }
        self.ret = (
            "# -*- coding: utf-8 -*-\n"
            "#!/usr/bin/env python3\n"
            "#\n"
            "# Copyright (C) 2019 Intel Corporation.  All rights reserved.\n"
            "# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"
            "#\n"
            "#It is a generated file. DO NOT EDIT.\n"
            "#\n"
            "from ctypes import *\n"
            "\n"
            "from .ffi import dereference, libiwasm, wasm_ref_t, wasm_val_t\n"
            "\n"
            "\n"
        )

    def get_type_name(self, c_type):
        if isinstance(c_type, c_ast.TypeDecl):
            return self.get_type_name(c_type.type)
        elif isinstance(c_type, c_ast.PtrDecl):
            pointed_type = self.get_type_name(c_type.type)

            if isinstance(c_type.type, c_ast.FuncDecl):
                # CFUCNTYPE is a pointer of function
                return pointed_type

            if "None" == pointed_type:
                return "c_void_p"

            return f"POINTER({pointed_type})"

        elif isinstance(c_type, c_ast.ArrayDecl):
            return f"POINTER({self.get_type_name(c_type.type)})"
        elif isinstance(c_type, c_ast.IdentifierType):
            if len(c_type.names) > 1:
                raise RuntimeError(f"unexpected type with a long names: {c_type}")

            type_name = c_type.names[0]

            if type_name.startswith("wasm_"):
                return type_name

            if not type_name in self.type_map:
                raise RuntimeError(f"a new type should be in type_map: {type_name}")

            return self.type_map.get(type_name)
        elif isinstance(c_type, c_ast.Union):
            if not c_type.name:
                raise RuntimeError(f"found an anonymous union {c_type}")

            return c_type.name
        elif isinstance(c_type, c_ast.Struct):
            if not c_type.name:
                raise RuntimeError(f"found an anonymous union {c_type}")

            return c_type.name
        elif isinstance(c_type, c_ast.FuncDecl):
            content = "CFUNCTYPE("
            if isinstance(c_type.type, c_ast.PtrDecl):
                # there is a bug in CFUNCTYPE if the result type is a pointer
                content += "c_void_p"
            else:
                content += f"{self.get_type_name(c_type.type)}"
            content += f",{self.get_type_name(c_type.args)}" if c_type.args else ""
            content += ")"
            return content
        elif isinstance(c_type, c_ast.Decl):
            return self.get_type_name(c_type.type)
        elif isinstance(c_type, c_ast.ParamList):
            content = ",".join(
                [self.get_type_name(param.type) for param in c_type.params]
            )
            return content
        else:
            raise RuntimeError(f"unexpected type: {c_type.show()}")

    def visit_Struct(self, node):
        # pylint: disable=invalid-name
        def gen_fields(info, indent):
            content = ""
            for k, v in info.items():
                content += f'{indent}("{k}", {v}),\n'
            return content[:-1]

        def gen_equal(info, indent):
            content = f"{indent}return"
            for k, v in info.items():
                # not compare pointer value in __eq__
                if v.startswith("POINTER") or v.startswith("c_void_p"):
                    continue

                content += f" self.{k} == other.{k} and"
            return content[:-4]

        def gen_repr(info, indent):
            content = f'{indent}return f"{{{{'
            for k, _ in info.items():
                content += f"{k}={{self.{k}}}, "
            content = content[:-2] + '}}"'
            return content

        def gen_vector_repr(info, indent):
            content = f'{indent}ret = ""\n'
            content += f"{indent}for i in range(self.num_elems):\n"

            if 1 == info["data"].count("POINTER"):
                # pointer
                content += f"{2*indent}ret += str(self.data[i])\n"
            else:
                # pointer of pointer
                content += f"{2*indent}ret += str(dereference(self.data[i]))\n"

            content += f'{2*indent}ret += " "\n'
            content += f"{indent}return ret\n"
            return content

        if not node.name or not node.name.lower().startswith("wasm"):
            return

        if node.name in IGNORE_SYMOLS:
            return

        name = node.name

        info = {}
        if node.decls:
            for decl in node.decls:
                info[decl.name] = self.get_type_name(decl.type)

        if info:
            self.ret += (
                f"class {name}(Structure):\n"
                f"{INDENT}_fields_ = [\n"
                f"{gen_fields(info, INDENT*2)}\n"
                f"{INDENT}]\n"
                f"\n"
                f"{INDENT}def __eq__(self, other):\n"
                f"{INDENT*2}if not isinstance(other, {name}):\n"
                f"{INDENT*3}return False\n"
                f"{gen_equal(info, INDENT*2)}\n"
                f"\n"
                f"{INDENT}def __repr__(self):\n"
            )
            self.ret += (
                f"{gen_vector_repr(info, INDENT*2)}\n"
                if name.endswith("_vec_t")
                else f"{gen_repr(info, INDENT*2)}\n"
            )
            self.ret += "\n"

        else:
            self.ret += f"class {name}(Structure):\n{INDENT}pass\n"

        self.ret += "\n"

    def visit_Union(self, node):
        # pylint: disable=invalid-name
        print(f"Union: {node.show()}")

    def visit_Typedef(self, node):
        # pylint: disable=invalid-name
        # system defined
        if not node.name:
            return

        if not node.name.startswith("wasm_"):
            return

        if node.name in IGNORE_SYMOLS:
            return

        self.visit(node.type)

        if node.name == self.get_type_name(node.type):
            return
        else:
            self.ret += f"{node.name} = {self.get_type_name(node.type)}\n"
            self.ret += "\n"

    def visit_FuncDecl(self, node):
        # pylint: disable=invalid-name
        restype = self.get_type_name(node.type)

        if isinstance(node.type, c_ast.TypeDecl):
            func_name = node.type.declname
        elif isinstance(node.type, c_ast.PtrDecl):
            func_name = node.type.type.declname
        else:
            raise RuntimeError(f"unexpected type in FuncDecl: {type}")

        if not func_name.startswith("wasm_") or func_name.endswith("_t"):
            return

        if func_name in IGNORE_SYMOLS:
            return

        params_len = 0
        for arg in node.args.params:
            # ignore void but not void*
            if isinstance(arg.type, c_ast.TypeDecl):
                type_name = self.get_type_name(arg.type)
                if "None" == type_name:
                    continue

            params_len += 1

        args = (
            "" if not params_len else ",".join([f"arg{i}" for i in range(params_len)])
        )
        argtypes = f"[{self.get_type_name(node.args)}]" if params_len else "None"

        self.ret += (
            f"def {func_name}({args}):\n"
            f"{INDENT}_{func_name} = libiwasm.{func_name}\n"
            f"{INDENT}_{func_name}.restype = {restype}\n"
            f"{INDENT}_{func_name}.argtypes = {argtypes}\n"
            f"{INDENT}return _{func_name}({args})\n"
        )
        self.ret += "\n"

    def visit_Enum(self, node):
        # pylint: disable=invalid-name
        elem_value = 0
        # generate enum elementes directly as consts with values
        for i, elem in enumerate(node.values.enumerators):
            self.ret += f"{elem.name}"

            if elem.value:
                elem_value = int(elem.value.value)
            else:
                if 0 == i:
                    elem_value = 0
                else:
                    elem_value += 1

            self.ret += f" = {elem_value}\n"

        self.ret += "\n"


def preflight_check(workspace):
    wamr_repo = workspace
    file_check_list = [
        wamr_repo.exists(),
        wamr_repo.joinpath(WASM_C_API_HEADER).exists(),
    ]

    if not all(file_check_list):
        print(
            "please run utils/download_wamr.py to download the repo, or re-download the repo"
        )
        return False

    if not shutil.which("gcc"):
        print("please install gcc")
        return False

    return True


def do_parse(workspace):
    filename = workspace.joinpath(WASM_C_API_HEADER)
    filename = str(filename)

    ast = parse_file(
        filename,
        use_cpp=True,
        cpp_path="gcc",
        cpp_args=[
            "-E",
            "-D__attribute__(x)=",
            "-D__asm__(x)=",
            "-D__asm(x)=",
            "-D__builtin_va_list=int",
            "-D__extension__=",
            "-D__inline__=",
            "-D__restrict=",
            "-D__restrict__=",
            "-D_Static_assert(x, y)=",
            "-D__signed=",
            "-D__volatile__(x)=",
            "-Dstatic_assert(x, y)=",
        ],
    )

    ast_visitor = Visitor()
    ast_visitor.visit(ast)
    return ast_visitor.ret


def main():
    current_file = pathlib.Path(__file__)
    if current_file.is_symlink():
        current_file = pathlib.Path(os.readlink(current_file))

    current_dir = current_file.parent.resolve()
    root_dir = current_dir.joinpath("../../../..").resolve()

    if not preflight_check(root_dir):
        return False

    wamr_repo = root_dir
    binding_file_path = root_dir.joinpath(BINDING_PATH)
    with open(binding_file_path, "wt", encoding="utf-8") as binding_file:
        binding_file.write(do_parse(wamr_repo))

    return True


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
