# Thread related embedder API

This document explains `wasm_runtime_spawn_exec_env` and
`wasm_runtime_spawn_thread`.
[Here](../samples/spawn-thread) is a sample to show how to use these APIs.

  * spawn exec_env

    `spawn exec_env` API creates a new `exec_env` based on the original `exec_env`. You can use it in other threads. It's up to the embedder how to manage host threads to run the new `exec_env`.

    ```C
    new_exec_env = wasm_runtime_spawn_exec_env(exec_env);

      /* Then you can use new_exec_env in your new thread */
      module_inst = wasm_runtime_get_module_inst(new_exec_env);
      func_inst = wasm_runtime_lookup_function(module_inst, ...);
      wasm_runtime_call_wasm(new_exec_env, func_inst, ...);

    /* you need to use this API to manually destroy the spawned exec_env */
    wasm_runtime_destroy_spawned_exec_env(new_exec_env);
    ```

  * spawn thread

    Alternatively, you can use `spawn thread` API to avoid managing the extra exec_env and the corresponding host thread manually:

    ```C
    wasm_thread_t wasm_tid;
    void *wamr_thread_cb(wasm_exec_env_t exec_env, void *arg)
    {
      module_inst = wasm_runtime_get_module_inst(exec_env);
      func_inst = wasm_runtime_lookup_function(module_inst, ...);
      wasm_runtime_call_wasm(exec_env, func_inst, ...);
    }
    wasm_runtime_spawn_thread(exec_env, &wasm_tid, wamr_thread_cb, NULL);
    /* Use wasm_runtime_join_thread to join the spawned thread */
    wasm_runtime_join_thread(wasm_tid, NULL);
    ```
