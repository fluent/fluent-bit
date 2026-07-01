# Wasm Function

## Internal data structure

![](./images/wasm_function.svg)

## Module level data (function)
**WASMModule**: Data structure created for loading a module.
- `WASMImport *import_functions`: initialized from the Wasm file function section
- `WASMImport *import_functions`: initialized from the Wasm file import section. The runtime will try to solve the imports from the native API registration, refer to [Export native API to WASM application](../../../doc/export_native_api.md).

**WASMFunction**: represent a Wasm function located in Wasm file code section. Track the links to the compiled function body.
**WASMImport**: represent a imported Wasm function which can be a solved as a native function or another Wasm module exported function.

## Instance level data (function)
**WASMModuleInstance**: Data structure created for instantiating a module
- `WASMModuleInstanceExtra::functions`: combined the imported and internal functions into single array of structure `WASMFunctionInstance`
- `WASMModuleInstance::import_func_ptrs`: pointer array for solved function imports. This array is referred during calling imported native function. Note it is initialized with the module level solved imports, but may points to different native function later due to c-api calls.

## Execution paths
**Interpreter**:
- Execute internal bytecode function:
    ```
    WASMModuleInstance::e
        -> WASMModuleInstanceExtra::functions[..]
            -> WASMFunctionInstance::func
                -> WASMFunction::code
    ```

- Execute imported function from other module:
    ```
    WASMModuleInstance::e
        -> WASMModuleInstanceExtra::functions[..]
            (WASMFunctionInstance flag indicates an import)
            -> WASMFunctionInstance::import_func_inst
                -> WASMModuleInstance(second)::func
                    -> WASMFunction (second module)::code
    ```

- Execute imported native function:
    ```
    WASMModuleInstance::e
        -> WASMModuleInstanceExtra::functions[..]
        (flag indicates imported native)
    WASMModuleInstance::import_func_ptrs[..]
        -> native function
    ```
