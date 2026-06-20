#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "wasm_c_api.h"

#define own


wasm_memory_t* get_export_memory(const wasm_extern_vec_t* exports, size_t i) {
  if (exports->size <= i || !wasm_extern_as_memory(exports->data[i])) {
    printf("> Error accessing memory export %zu!\n", i);
    exit(1);
  }
  return wasm_extern_as_memory(exports->data[i]);
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

void check_call(wasm_func_t* func, int i, wasm_val_t args[], int32_t expected) {
  wasm_val_t r[] = {WASM_INIT_VAL};
  wasm_val_vec_t args_ = {i, args, i, sizeof(wasm_val_t), NULL};
  wasm_val_vec_t results = WASM_ARRAY_VEC(r);
  wasm_trap_t *trap = wasm_func_call(func, &args_, &results);
  if (trap) {
      printf("> Error on result\n");
      wasm_trap_delete(trap);
      exit(1);
  }

  if (r[0].of.i32 != expected) {
      printf("> Error on result\n");
      exit(1);
  }
}

void check_call0(wasm_func_t* func, int32_t expected) {
  check_call(func, 0, NULL, expected);
}

void check_call1(wasm_func_t* func, int32_t arg, int32_t expected) {
  wasm_val_t args[] = { WASM_I32_VAL(arg) };
  check_call(func, 1, args, expected);
}

void check_call2(wasm_func_t* func, int32_t arg1, int32_t arg2, int32_t expected) {
  wasm_val_t args[] = { WASM_I32_VAL(arg1), WASM_I32_VAL(arg2) };
  check_call(func, 2, args, expected);
}

void check_ok(wasm_func_t* func, int i, wasm_val_t args[]) {
  wasm_val_vec_t args_ = {i, args, i, sizeof(wasm_val_t), NULL};
  wasm_val_vec_t results = WASM_EMPTY_VEC;
  wasm_trap_t *trap = wasm_func_call(func, &args_, &results);
  if (trap) {
      printf("> Error on result, expected empty\n");
      wasm_trap_delete(trap);
      exit(1);
  }
}

void check_ok2(wasm_func_t* func, int32_t arg1, int32_t arg2) {
  wasm_val_t args[] = { WASM_I32_VAL(arg1), WASM_I32_VAL(arg2) };
  check_ok(func, 2, args);
}

void check_trap(wasm_func_t* func, int i, wasm_val_t args[]) {
  wasm_val_t r[] = {WASM_INIT_VAL};
  wasm_val_vec_t args_ = {i, args, i, sizeof(wasm_val_t), NULL};
  wasm_val_vec_t results = WASM_ARRAY_VEC(r);
  own wasm_trap_t* trap = wasm_func_call(func, &args_, &results);
  if (! trap) {
    printf("> Error on result, expected trap\n");
    exit(1);
  }
  wasm_trap_delete(trap);
}

void check_trap1(wasm_func_t* func, int32_t arg) {
  wasm_val_t args[] = { WASM_I32_VAL(arg) };
  check_trap(func, 1, args);
}

void check_trap2(wasm_func_t* func, int32_t arg1, int32_t arg2) {
  wasm_val_t args[] = { WASM_I32_VAL(arg1), WASM_I32_VAL(arg2) };
  check_trap(func, 2, args);
}


int main(int argc, const char* argv[]) {
  // Initialize.
  printf("Initializing...\n");
  wasm_engine_t* engine = wasm_engine_new();
  wasm_store_t* store = wasm_store_new(engine);

  // Load binary.
  printf("Loading binary...\n");
#if WASM_ENABLE_AOT != 0 && WASM_ENABLE_INTERP == 0
  FILE* file = fopen("memory.aot", "rb");
#else
  FILE* file = fopen("memory.wasm", "rb");
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
  own wasm_instance_t *instance = wasm_instance_new_with_args(
      store, module, &imports, NULL, KILOBYTE(32), 0);
  if (!instance) {
    printf("> Error instantiating module!\n");
    return 1;
  }

  // Extract export.
  printf("Extracting exports...\n");
  own wasm_extern_vec_t exports;
  wasm_instance_exports(instance, &exports);
  size_t i = 0;
  wasm_memory_t* memory = get_export_memory(&exports, i++);
  wasm_func_t* size_func = get_export_func(&exports, i++);
  wasm_func_t* load_func = get_export_func(&exports, i++);
  wasm_func_t* store_func = get_export_func(&exports, i++);

  wasm_module_delete(module);

  // Try cloning.
  own wasm_memory_t* copy = wasm_memory_copy(memory);
  assert(wasm_memory_same(memory, copy));
  wasm_memory_delete(copy);

  // Check initial memory.
  printf("Checking memory...\n");
  check(wasm_memory_size(memory) == 2);
  check(wasm_memory_data_size(memory) == 0x20000);
  check(wasm_memory_data(memory)[0] == 0);
  check(wasm_memory_data(memory)[0x1000] == 1);
  check(wasm_memory_data(memory)[0x1003] == 4);

  check_call0(size_func, 2);
  check_call1(load_func, 0, 0);
  check_call1(load_func, 0x1000, 1);
  check_call1(load_func, 0x1003, 4);
  check_call1(load_func, 0x1ffff, 0);
  check_trap1(load_func, 0x20000);

  // Mutate memory.
  printf("Mutating memory...\n");
  wasm_memory_data(memory)[0x1003] = 5;
  check_ok2(store_func, 0x1002, 6);
  check_trap2(store_func, 0x20000, 0);

  check(wasm_memory_data(memory)[0x1002] == 6);
  check(wasm_memory_data(memory)[0x1003] == 5);
  check_call1(load_func, 0x1002, 6);
  check_call1(load_func, 0x1003, 5);

  // Grow memory.
  // DO NOT SUPPORT
  printf("Bypass Growing memory...\n");
  wasm_extern_vec_delete(&exports);
  wasm_instance_delete(instance);

  // Create stand-alone memory.
  // DO NOT SUPPORT
  // TODO(wasm+): Once Wasm allows multiple memories, turn this into import.
  printf("Bypass Creating stand-alone memory...\n");

  // Shut down.
  printf("Shutting down...\n");
  wasm_store_delete(store);
  wasm_engine_delete(engine);

  // All done.
  printf("Done.\n");
  return 0;
}
