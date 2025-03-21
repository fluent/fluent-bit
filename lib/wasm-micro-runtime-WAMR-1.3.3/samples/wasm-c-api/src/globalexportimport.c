/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "wasm_c_api.h"
#include "wasm_export.h"
#include "bh_platform.h"

extern bool
reader(const char *module_name, uint8 **p_buffer, uint32 *p_size);

extern void
destroyer(uint8 *buffer, uint32 size);

#define own

wasm_global_t* get_export_global(const wasm_extern_vec_t* exports, size_t i) {
  if (exports->size <= i || !wasm_extern_as_global(exports->data[i])) {
    printf("> Error accessing global export %zu!\n", i);
    exit(1);
  }
  return wasm_extern_as_global(exports->data[i]);
}

wasm_func_t* get_export_func(const wasm_extern_vec_t* exports, size_t i) {
  if (exports->size <= i || !wasm_extern_as_func(exports->data[i])) {
    printf("> Error accessing function export %zu!\n", i);
    exit(1);
  }
  return wasm_extern_as_func(exports->data[i]);
}


#define check(val, type, expected) \
  if (val.of.type != expected) { \
    printf("> Expected reading value %f or %f \n", expected, expected); \
    printf("> Error reading value %f or %f\n", val.of.type, val.of.type); \
  }

#define check_global(global, type, expected) \
  { \
    wasm_val_t val; \
    wasm_global_get(global, &val); \
    check(val, type, expected); \
  }

#define check_trap(trap)                      \
    if (trap) {                               \
        printf("> Error calling function\n"); \
        wasm_trap_delete(trap);               \
        exit(1);                              \
    }

#define check_call(func, type, expected)                          \
    {                                                             \
        wasm_val_vec_t results;                                   \
        wasm_val_vec_new_uninitialized(&results, 1);              \
        wasm_trap_t *trap = wasm_func_call(func, NULL, &results); \
        check_trap(trap);                                         \
        check(results.data[0], type, expected);                   \
    }

wasm_module_t * create_module_from_file(wasm_store_t* store, const char * filename)
{
  FILE* file = fopen(filename, "rb");
  fseek(file, 0L, SEEK_END);
  size_t file_size = ftell(file);
  fseek(file, 0L, SEEK_SET);
  wasm_byte_vec_t binary;
  wasm_byte_vec_new_uninitialized(&binary, file_size);
  if (fread(binary.data, file_size, 1, file) != 1) {
    printf("> Error loading module!\n");
    fclose(file);
    return NULL;
  }
  // Compile.
  printf("Compiling module...\n");
  own wasm_module_t* module = wasm_module_new(store, &binary);
  if (!module) {
    printf("> Error compiling module!\n");
    return NULL;
  }
  wasm_byte_vec_delete(&binary);
  fclose(file);
  return module;
}


int main(int argc, const char* argv[]) {
  wasm_runtime_set_module_reader(reader, destroyer);

  // Initialize.
  printf("Initializing...\n");
  wasm_engine_t* engine = wasm_engine_new();
  wasm_store_t* store = wasm_store_new(engine);

  // Load binary.
  printf("Loading binary...\n");
#if WASM_ENABLE_AOT != 0 && WASM_ENABLE_INTERP == 0
  wasm_module_t* moduleimport =
      create_module_from_file(store, "globalimport.aot");
#else
  wasm_module_t* moduleimport =
      create_module_from_file(store, "globalexportimport-1.wasm");
#endif

  if (!moduleimport) {
      return 1;
  }

  // Instantiate.
  printf("Instantiating Import module...\n");
  own wasm_instance_t* instance_import =
    wasm_instance_new(store, moduleimport, NULL, NULL); //after this var_f32_export->inst_comm_rt is module_import
  if (!instance_import) {
    printf("> Error instantiating Import module!\n");
    return 1;
  }
  wasm_module_delete(moduleimport);

  // Extract export.
  printf("Extracting exports from Import module...\n");
  own wasm_extern_vec_t exports_of_import;
  wasm_instance_exports(instance_import, &exports_of_import);
  int i = 0;
  wasm_global_t *var_f32_export = get_export_global(&exports_of_import, i++);
  wasm_func_t *get_var_f32_export = get_export_func(&exports_of_import, i++);
  wasm_func_t* set_var_f32_export = get_export_func(&exports_of_import, i++);
  wasm_func_t* get_var_f32_import = get_export_func(&exports_of_import, i++);
  wasm_func_t* set_var_f32_import = get_export_func(&exports_of_import, i++);

  // Interact.

  // Check initial values.
  printf("Check initial values...\n");
  check_global(var_f32_export, f32, 7.0);
  check_call(get_var_f32_export, f32, 7.0); //Call to module export
  check_call(get_var_f32_import, f32, 7.0); //Call to module import


  // Modify variables through API and check again.
  printf("Modify the variable to 37.0...\n");
  wasm_val_t val37 = {.kind = WASM_F32, .of = {.f32 = 37.0}};
  wasm_global_set(var_f32_export, &val37);  //  var_f32_export->inst_comm_rt is module_import now

  check_global(var_f32_export, f32, 37.0);
  check_call(get_var_f32_export, f32, 37.0); //Call to module export  Failed here, still 7
  check_call(get_var_f32_import, f32, 37.0); //Call to module import

  // Modify variables through calls and check again.
  printf("Modify the variable to 77.0...\n");
  wasm_val_vec_t args77;
  wasm_val_vec_new(&args77, 1, (wasm_val_t []){ {.kind = WASM_F32, .of = {.f32 = 77.0}} });
  wasm_trap_t *trap = wasm_func_call(set_var_f32_export, &args77,
                                     NULL); // Call to module export
  check_trap(trap);
  check_call(get_var_f32_export, f32, 77.0);          //Call to module export
  check_global(var_f32_export, f32, 77.0);    //Failed here, still 37
  check_call(get_var_f32_import, f32, 77.0); //Call to module import  Failed here, still 37


  printf("Modify the variable to 78.0...\n");
  wasm_val_vec_t args78;
  wasm_val_vec_new(&args78, 1, (wasm_val_t []){ {.kind = WASM_F32, .of = {.f32 = 78.0}} });
  trap = wasm_func_call(set_var_f32_import, &args78, NULL);
  check_trap(trap);
  check_global(var_f32_export, f32, 78.0);
  check_call(get_var_f32_export, f32, 78.0); //Call to module export Failed here, still 77
  check_call(get_var_f32_import, f32, 78.0); //Call to module import


  // wasm_extern_vec_delete(&exports_of_export);
  //wasm_instance_delete(instance_export);
  wasm_extern_vec_delete(&exports_of_import);
  //wasm_instance_delete(instance_import);

  // Shut down.
  printf("Shutting down...\n");
  wasm_store_delete(store);
  wasm_engine_delete(engine);

  // All done.
  printf("Done.\n");
  return 0;

}
