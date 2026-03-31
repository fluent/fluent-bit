#!/usr/bin/env python3
#
# Copyright (C) 2021 XiaoMi Corporation. All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
import gdb

# Get object file path from environment variable or use default value
path_objs = os.getenv("OBJ_PATH", "~/objects/")

# Expand user directory symbol (~)
path_objs = os.path.expanduser(path_objs)
print(f"Object files will be loaded from: {path_objs} on localhost")


def add_symbol_with_aot_info(aot_module_info):
    """Add symbol file with AOT information to GDB and list current breakpoints."""
    try:
        text_addr = aot_module_info.get("code")
        file_name = aot_module_info.get("name")

        if not text_addr or not file_name:
            print("Error: 'code' or 'name' missing in AOT module info.")
            return

        # Extract base file name without extension
        file_name_without_extension, _ = os.path.splitext(file_name)

        # Remove directory part if present
        file_name = os.path.basename(file_name_without_extension)

        # Add .obj extension to the file name
        file_name = file_name + ".obj"

        # Construct the path for the symbol file
        path_symfile = os.path.join(path_objs, file_name)

        # Construct the command to add the symbol file
        cmd = f"add-symbol-file {path_symfile} {text_addr}"
        gdb.execute(cmd)

        # Print current breakpoints
        breakpoints = gdb.execute("info breakpoints", to_string=True)
        print("Current breakpoints:", breakpoints)

    except gdb.error as e:
        print(f"GDB error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


class ReadGDynamicAotModule(gdb.Command):
    """Command to read the g_dynamic_aot_module structure and extract information."""

    def __init__(self):
        super(self.__class__, self).__init__("read_gda", gdb.COMMAND_USER)

    def invoke(self, args, from_tty):
        """Retrieve and process the g_dynamic_aot_module structure."""
        try:
            aot_module = gdb.parse_and_eval("g_dynamic_aot_module")
            aot_module_info = {}

            # Ensure aot_module is a pointer and dereference it
            if aot_module.type.code == gdb.TYPE_CODE_PTR:
                aot_module = aot_module.dereference()

                # Check if it's a structure type
                if aot_module.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT:
                    for field in aot_module.type.fields():
                        field_name = field.name
                        var = aot_module[field_name]

                        if field_name == "name":
                            aot_module_info["name"] = var.string()
                        elif field_name == "code":
                            aot_module_info["code"] = str(var)

                    if "name" in aot_module_info and "code" in aot_module_info:
                        add_symbol_with_aot_info(aot_module_info)
                    else:
                        print("Could not find 'name' or 'code' in Aot_module.")
                else:
                    print("Aot_module is not of struct type.")
            else:
                print("Aot_module is not a pointer type.")
        except gdb.error as e:
            print(f"An error occurred: {e}")


def init():
    """Initialize environment and set up debugger."""
    # Register the command to gdb
    ReadGDynamicAotModule()

    # Set a breakpoint at function __enable_dynamic_aot_debug
    breakpoint = gdb.Breakpoint("__enable_dynamic_aot_debug")
    # Attach the self-defined command to the created breakpoint, read_gda means read global dynamic aot info.
    breakpoint.commands = "read_gda"


init()
