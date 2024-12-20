#include <stdio.h>

#include "wasm_c_api.h"

#define own

int main(int argc, const char* argv[]) {
  // Initialize.
  printf("Initializing...\n");
  wasm_engine_t* engine = wasm_engine_new();
  wasm_store_t* store = wasm_store_new(engine);

  // Load binary.
  printf("Loading binary...\n");
#if WASM_ENABLE_AOT != 0 && WASM_ENABLE_INTERP == 0
  FILE* file = fopen("empty_imports.aot", "rb");
#else
  FILE* file = fopen("empty_imports.wasm", "rb");
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

  // Instantiate with non-null but empty imports array.
  printf("Instantiating module...\n");
  wasm_extern_vec_t imports = WASM_EMPTY_VEC;
  own wasm_instance_t* instance =
    wasm_instance_new(store, module, &imports, NULL);
  if (!instance) {
    printf("> Error instantiating module!\n");
    return 1;
  }

  // Run an exported function to verify that the instance was created correctly.
  printf("Extracting export...\n");
  own wasm_extern_vec_t exports;
  wasm_instance_exports(instance, &exports);
  if (exports.size == 0) {
    printf("> Error accessing exports!\n");
    return 1;
  }

  const wasm_func_t* add_func = wasm_extern_as_func(exports.data[0]);
  if (add_func == NULL) {
    printf("> Error accessing export!\n");
    return 1;
  }

  wasm_module_delete(module);
  wasm_instance_delete(instance);

  printf("Calling export...\n");
  wasm_val_t args[2] = { WASM_I32_VAL(3), WASM_I32_VAL(4) };
  wasm_val_vec_t args_vec = WASM_ARRAY_VEC(args);

  wasm_val_t results[1] = { WASM_INIT_VAL };
  wasm_val_vec_t results_vec = WASM_ARRAY_VEC(results);

  wasm_trap_t *trap = wasm_func_call(add_func, &args_vec, &results_vec);
  if (trap) {
      printf("> Error calling function!\n");
      wasm_trap_delete(trap);
      return 1;
  }

  if (results_vec.data[0].of.i32 != 7) {
      printf("> Error calling function!\n");
      return 1;
  }

  wasm_extern_vec_delete(&exports);

  // Shut down.
  printf("Shutting down...\n");
  wasm_store_delete(store);
  wasm_engine_delete(engine);

  // All done.
  printf("Done.\n");
  return 0;
}
