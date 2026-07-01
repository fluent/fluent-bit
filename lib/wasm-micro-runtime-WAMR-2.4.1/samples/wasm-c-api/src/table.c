#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "wasm_c_api.h"

#define own

// A function to be called from Wasm code.
own wasm_trap_t* neg_callback(
  const wasm_val_vec_t* args, wasm_val_vec_t* results
) {
  printf("Calling back...\n");
  results->data[0].kind = WASM_I32;
  results->data[0].of.i32 = -args->data[0].of.i32;
  return NULL;
}


wasm_table_t* get_export_table(const wasm_extern_vec_t* exports, size_t i) {
  if (exports->size <= i || !wasm_extern_as_table(exports->data[i])) {
    printf("> Error accessing table export %zu!\n", i);
    exit(1);
  }
  return wasm_extern_as_table(exports->data[i]);
}

wasm_func_t* get_export_func(const wasm_extern_vec_t* exports, size_t i) {
  if (exports->size <= i || !wasm_extern_as_func(exports->data[i])) {
    printf("> Error accessing function export %zu!\n", i);
    exit(1);
  }
  return wasm_extern_as_func(exports->data[i]);
}


void check(bool success) {
  if (!success) {
    printf("> Error, expected success\n");
    exit(1);
  }
}

void check_table(wasm_table_t* table, int32_t i, bool expect_set) {
  own wasm_ref_t* ref = wasm_table_get(table, i);
  check((ref != NULL) == expect_set);
  if (ref) wasm_ref_delete(ref);
}

void check_call(wasm_func_t* func, int32_t arg1, int32_t arg2, int32_t expected) {
  wasm_val_t vs[2] = { WASM_I32_VAL(arg1), WASM_I32_VAL(arg2) };
  wasm_val_t r[1] = { WASM_INIT_VAL };
  wasm_val_vec_t args = WASM_ARRAY_VEC(vs);
  wasm_val_vec_t results = WASM_ARRAY_VEC(r);
  wasm_trap_t *trap = wasm_func_call(func, &args, &results);
  if (trap) {
      printf("> Error on calling\n");
      wasm_trap_delete(trap);
      exit(1);
  }

  if (r[0].of.i32 != expected) {
      printf("> Error on result\n");
      exit(1);
  }
}

void check_trap(wasm_func_t* func, int32_t arg1, int32_t arg2) {
  wasm_val_t vs[2] = { WASM_I32_VAL(arg1), WASM_I32_VAL(arg2) };
  wasm_val_t r[1] = { WASM_INIT_VAL };
  wasm_val_vec_t args = WASM_ARRAY_VEC(vs);
  wasm_val_vec_t results = WASM_ARRAY_VEC(r);
  own wasm_trap_t* trap = wasm_func_call(func, &args, &results);
  if (! trap) {
    printf("> Error on result, expected trap\n");
    exit(1);
  }
  wasm_trap_delete(trap);
}


int main(int argc, const char* argv[]) {
  // Initialize.
  printf("Initializing...\n");
  wasm_engine_t* engine = wasm_engine_new();
  wasm_store_t* store = wasm_store_new(engine);

  // Load binary.
  printf("Loading binary...\n");
#if WASM_ENABLE_AOT != 0 && WASM_ENABLE_INTERP == 0
  FILE* file = fopen("table.aot", "rb");
#else
  FILE* file = fopen("table.wasm", "rb");
#endif
  if (!file) {
    printf("> Error loading module!\n");
    return 1;
  }

  int ret = fseek(file, 0L, SEEK_END);
  if (ret == -1) {
    printf("> Error loading module!\n");
    fclose(file);
    return 1;
  }

  long file_size = ftell(file);
  if (file_size == -1) {
    printf("> Error loading module!\n");
    fclose(file);
    return 1;
  }

  ret = fseek(file, 0L, SEEK_SET);
  if (ret == -1) {
    printf("> Error loading module!\n");
    fclose(file);
    return 1;
  }

  wasm_byte_vec_t binary;
  wasm_byte_vec_new_uninitialized(&binary, file_size);
  if (fread(binary.data, file_size, 1, file) != 1) {
    printf("> Error loading module!\n");
    fclose(file);
    return 1;
  }
  fclose(file);

  // Compile.
  printf("Compiling module...\n");
  own wasm_module_t* module = wasm_module_new(store, &binary);
  if (!module) {
    printf("> Error compiling module!\n");
    return 1;
  }

  wasm_byte_vec_delete(&binary);

  // Instantiate.
  printf("Instantiating module...\n");
  wasm_extern_vec_t imports = WASM_EMPTY_VEC;
  own wasm_instance_t* instance =
    wasm_instance_new(store, module, &imports, NULL);
  if (!instance) {
    printf("> Error instantiating module!\n");
    return 1;
  }

  // Extract export.
  printf("Extracting exports...\n");
  own wasm_extern_vec_t exports;
  wasm_instance_exports(instance, &exports);
  size_t i = 0;
  wasm_table_t* table = get_export_table(&exports, i++);
  wasm_func_t* call_indirect = get_export_func(&exports, i++);
  wasm_func_t* f = get_export_func(&exports, i++);
  wasm_func_t* g = get_export_func(&exports, i++);

  wasm_module_delete(module);

  // Create external function.
  printf("Creating callback...\n");
  own wasm_functype_t* neg_type = wasm_functype_new_1_1(wasm_valtype_new_i32(), wasm_valtype_new_i32());
  own wasm_func_t* h = wasm_func_new(store, neg_type, neg_callback);

  wasm_functype_delete(neg_type);

  // Try cloning.
  own wasm_table_t* copy = wasm_table_copy(table);
  assert(wasm_table_same(table, copy));
  wasm_table_delete(copy);

  // Check initial table.
  printf("Checking table...\n");
  check(wasm_table_size(table) == 2);
  check_table(table, 0, false);
  check_table(table, 1, true);
  check_trap(call_indirect, 0, 0);
  check_call(call_indirect, 7, 1, 7);
  check_trap(call_indirect, 0, 2);

  // Mutate table.
  printf("Mutating table...\n");
  check(wasm_table_set(table, 0, wasm_func_as_ref(g)));
  check(wasm_table_set(table, 1, NULL));
  wasm_ref_t *ref_f = wasm_func_as_ref(f);
  check(! wasm_table_set(table, 2, ref_f));
  wasm_ref_delete(ref_f);
  check_table(table, 0, true);
  check_table(table, 1, false);
  check_call(call_indirect, 7, 0, 666);
  check_trap(call_indirect, 0, 1);
  check_trap(call_indirect, 0, 2);

  // Grow table.
  // DO NOT SUPPORT
  printf("Bypass Growing table...\n");

  wasm_func_delete(h);
  wasm_extern_vec_delete(&exports);
  wasm_instance_delete(instance);

  // Create stand-alone table.
  // DO NOT SUPPORT
  // TODO(wasm+): Once Wasm allows multiple tables, turn this into import.
  printf("Bypass Creating stand-alone table...\n");

  // Shut down.
  printf("Shutting down...\n");
  wasm_store_delete(store);
  wasm_engine_delete(engine);

  // All done.
  printf("Done.\n");
  return 0;
}
