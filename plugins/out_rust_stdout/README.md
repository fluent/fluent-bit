# Rust for Fluent-bit

We’ve successfully built a prototype Rust output plugin that:

1. leverages the C plugin header files with no new proxy C code needed in the core codebase.
2. uses the new plugin registration mechanism (i.e. top-level struct variable in each plugin).
3. was linked into the final fluent-bit executable as a static library. Just like all the other built-in C plugins and internal core libraries.

The above experiment implies that arbitrary Rust code can live alongside Fluent-bit’s C codebase to complement it via the addition of new plugins or new libraries that call/callable from the rest of the Fluent-bit C codebase with virtually 0 overhead.

## Details

The PoC consists of 2 crates (i.e. Rust packages): `rust_binding` and `out_rust_stdout`.
![Compilation workflow](https://raw.githubusercontent.com/hencrice/fluent-bit/rustPlugin/plugins/out_rust_stdout/details.png)

### rust_binding

This package uses [rust-bindgen](https://github.com/rust-lang/rust-bindgen) and the C header files from Fluent-bit to semi-automatically generate all the FFI (foreign function interface) binding needed to communicate with C. The package directory structure looks like the following:

```
fluent-bit/plugins/rust_binding
├── Cargo.toml
├── build.rs
├── src
│   └── lib.rs
└── wrapper.h
```

`wapper.h` references all the C header files we wish to generate Rust binding from:

```
# content of wrapper.h
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
```

When a crate contains a `build.rs` file, the Rust compiler will build and runs this program before actually compiling the crate. In rust_binding’s `build.rs`, it instructs rust-bindgen to use the `wrapper.h` file to only generate FFI bindings for those whitelisted functions/types. A snippet as follows:

```
fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let mut binding_builder = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .whitelist_function("flb_config_map_set")
        .whitelist_function("flb_output_get_property")
        .whitelist_function("flb_pack_to_json_format_type")
        .whitelist_function("flb_pack_to_json_date_type")
        .whitelist_function("flb_config_map_set")
        .whitelist_function("flb_output_set_context")
        .whitelist_function("flb_output_return_non_inline")
        .whitelist_function("flb_get_pthread")
        .whitelist_function("mk_event_add")
        .whitelist_function("mk_event_del")
        .whitelist_function("flb_thread_yield_non_inline")
        .whitelist_function("flb_thread_resume_non_inline")
        .whitelist_type("flb_input_instance")
        .whitelist_type("flb_filter_instance")
        .whitelist_type("flb_output_instance")
        .whitelist_type("flb_thread")
        .derive_debug(true)
        // blacklist the following 3 so that bindgen
        // does not generate another type with the
        // same name, which conflicts with my adapted version
        // in lib.rs
        .blacklist_type("flb_input_plugin")
        .blacklist_type("flb_filter_plugin")
        .blacklist_type("flb_output_plugin")
        .blacklist_type("flb_sds_t")
        .blacklist_type("flb_net_host")
......
```

A typical FFI Rust struct generated from the corresponding C definition that lives in a header file looks like this:

```
// In flb_network.h
struct flb_net_host {
    int  ipv6;             /* IPv6 required ?      */
    char *address;         /* Original address     */
    int   port;            /* TCP port             */
    char *name;            /* Hostname             */
    char *listen;          /* Listen interface     */
    struct flb_uri *uri;   /* Extra URI parameters */
};

// Generated Rust FFI
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct flb_net_host {
    pub ipv6: ::std::os::raw::c_int,
    pub address: *const ::std::os::raw::c_char,
    pub port: ::std::os::raw::c_int,
    pub name: *const ::std::os::raw::c_char,
    pub listen: *const ::std::os::raw::c_char,
    pub uri: *const flb_uri,
}
```

After this package is compiled, we have all the necessary code to interface C from Rust.

### out_rust_stdout

```
fluent-bit/plugins/out_rust_stdout
├── CMakeLists.txt
├── Cargo.lock
├── Cargo.toml
├── README.md
└── src
    └── lib.rs
```

The `out_rust_stdout` crate depends on the `rust_binding` crate and is free to pull in any additional dependencies by simply adding a few lines in Cargo.toml, which looks like the following (you can think of this file as Golang’s go.mod):

```
# content of Cargo.toml
[package]
name = "flb-plugin-out_rust_stdout"
version = "0.1.0"
authors = ["Yenlin Chen <3822365+hencrice@users.noreply.github.com>"]
edition = "2018"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
rust_binding={path="../rust_binding"}
serde={version="~1.0", features = ["derive"]}
rmp-serde="~0.14"

[lib]
 # Creates static lib to be liniked by the final fluent-bit executable:
 # https://doc.rust-lang.org/reference/linkage.html
crate-type=["staticlib"]
```

Note that the crate-type is `staticlib`. This means that the crate will be built as a C static library.

The `src/lib.rs` contains the majority of code of this PoC plugin. One of the Rust function that is registered as a callback for the C side of Fluent-bit looks like this:

```
#[no_mangle]
extern "C" fn plugin_flush(
    data: *const c_void,
    bytes: usize,
    tag: *const c_char,
    tag_len: c_int,
    i_ins: *mut rust_binding::flb_input_instance,
    out_context: *mut c_void,
    config: *mut rust_binding::flb_config,
) {
    unsafe {
        // some unsafe code to deal with C inputs. For example,
        // to cast c_void pointer to the actual data of a concrete type
    }
    
    // Do all the processing in Safe Rust :)
    
    // If we ever want to call C, must use unsafe
    unsafe {
        rust_binding::flb_output_return_non_inline(FLB_OK);
    }
}
```

Note that unsafe Rust does not disable all of Rust safety features but only allow you do certain unsafe operations [[link](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html#unsafe-superpowers)].

To build the Rust crate alongside the rest of Fluent-bit’s C codebase, I integrated with the rest of the project’s compilation workflow through the use of a new custom CMake macro:

```
macro(FLB_RUST_PLUGIN crate_name)
  if (CMAKE_BUILD_TYPE STREQUAL "Debug")
      set(CARGO_CMD cargo build)
  else ()
      set(CARGO_CMD cargo build --release)
  endif ()

  include(ExternalProject)
  # Set default ExternalProject root directory
  set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/Rust)

  get_directory_property(dirs INCLUDE_DIRECTORIES)
  set(bindgen_includes "")
  foreach(dir IN LISTS dirs)
      set(bindgen_includes ${bindgen_includes} -I${dir})
  endforeach()
  # bindgen_includes is a ";" seperated list in the form of a string
  # so replace all ; with " ", otherwise when we pass the bindgen_includes
  # variable to the CARGO_CMD below, bash will interpret the ";" character as
  # the end of COMMAND, which is incorrect.
  string(REPLACE ";" " " bindgen_includes "${bindgen_includes}")
  message(STATUS, "Rust bindgen_includes: ${bindgen_includes}")

  ExternalProject_Add(
    flb-plugin-${crate_name}_target
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${CMAKE_ARCHIVE_OUTPUT_DIRECTORY} BINDGEN_HEADER_DIRS=${bindgen_includes} ${CARGO_CMD}
    BINARY_DIR "${CMAKE_SOURCE_DIR}/plugins/${crate_name}"
    TEST_COMMAND ${CMAKE_COMMAND} -E env BINDGEN_HEADER_DIRS=${bindgen_includes} cargo test --lib --manifest-path "${CMAKE_SOURCE_DIR}/plugins/rust_binding/Cargo.toml" COMMAND ${CMAKE_COMMAND} -E env BINDGEN_HEADER_DIRS=${bindgen_includes} cargo test
    INSTALL_COMMAND ""
    LOG_BUILD ON
    LOG_OUTPUT_ON_FAILURE ON)
  add_sanitizers(flb-plugin-${crate_name}_target)

  add_library(flb-plugin-${crate_name} STATIC IMPORTED GLOBAL)
  add_dependencies(flb-plugin-${crate_name} flb-plugin-${crate_name}_target)
  if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(ARCHIVE_DEBUG ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/debug/libflb_plugin_${crate_name}.a)
    message(STATUS, "fluent-bit-bin will linked with ${ARCHIVE_DEBUG}") 
    set_target_properties(flb-plugin-${crate_name}
      PROPERTIES
      IMPORTED_LOCATION ${ARCHIVE_DEBUG})
  else ()
    set(ARCHIVE_OPTIMIZED ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/release/libflb_plugin_${crate_name}.a)
    message(STATUS, "fluent-bit-bin will linked with ${ARCHIVE_OPTIMIZED}") 
    set_target_properties(flb-plugin-${crate_name}
      PROPERTIES
      IMPORTED_LOCATION ${ARCHIVE_OPTIMIZED})
  endif ()

  add_dependencies(fluent-bit-bin flb-plugin-${crate_name})
  target_link_libraries(fluent-bit-bin flb-plugin-${crate_name})
endmacro()
```

In `out_rust_stdout`‘s CMakeList.txt, we simply use the macro as:

```
# content of fluent-bit/plugin/out_rust_stdout/CMakeLists.txt
FLB_RUST_PLUGIN(out_rust_stdout)
```

### What about input plugins?

I scanned through the code of some existing input plugins. The core requirement for all input plugins is the [flb_input_chunk_append_raw](https://github.com/fluent/fluent-bit/blob/baff15640e97ac46d457aab011e9103f2dca53ce/src/flb_input_chunk.c#L390) function, which is used to ingest data from an external source into Fluent bit (internally, that function writes to either memory or file system [here](https://github.com/fluent/fluent-bit/blob/66837f34b96a5509afce431031b43901bb071f96/lib/chunkio/src/cio_chunk.c#L154)). Rust can reuse this function directly.

Fluent-bit’s event loop is only used for those plugins that need to accept incoming connections, such as [in_forward](https://github.com/fluent/fluent-bit/blob/baff15640e97ac46d457aab011e9103f2dca53ce/plugins/in_forward/fw_conn.c#L137), [in_mqtt](https://github.com/fluent/fluent-bit/blob/baff15640e97ac46d457aab011e9103f2dca53ce/plugins/in_mqtt/mqtt_conn.c#L100), [in_syslog](https://github.com/fluent/fluent-bit/blob/baff15640e97ac46d457aab011e9103f2dca53ce/plugins/in_syslog/syslog_conn.c#L134), [in_tcp](https://github.com/fluent/fluent-bit/blob/baff15640e97ac46d457aab011e9103f2dca53ce/plugins/in_tcp/tcp_conn.c#L318), and the connections are passed in the form of file descriptor, which Rust can handle.

In short, I don’t see a technical blocker here.

### What about filter plugins?

Read through a few filters and all of them manipulate [in-memory data structures directly given](https://github.com/fluent/fluent-bit/blob/baff15640e97ac46d457aab011e9103f2dca53ce/plugins/filter_rewrite_tag/rewrite_tag.c#L298) to the filter callback that each filter implements. So no technical blocker here.

### Scaling of output plugins

One factor to consider for output plugins is the possibility to implement async I/O.

There are 2 options here:

1. the Rust plugin should rely on fluent-bit’s internal I/O event loop or
2. just leave async behavior entirely to the plugin (i.e. with its own event loop). This is the model used by Fluent-bit’s Go plugin.

After investigating, I found that for option 1, fluent-bit’s own event loop (more specifically, [_mk_event_add](https://github.com/fluent/fluent-bit/blob/baff15640e97ac46d457aab011e9103f2dca53ce/lib/monkey/mk_core/mk_event_epoll.c#L134)) heavily relies on epolling raw socket file descriptor. This means that to integrate with fluent-bit’s event loop, you’ll need access to the underlying fd.

It’s technically possible to write such a client in Rust, however, most of the Rust libraries provide async operations in the form of futures/promises to encapsulate the underlying OS async primitives (such as epoll) and do not provide explicit access to the underlying file descriptors. So it might be nontrivial if we want an idiomatic solution that leverages the high-level future concept but still works with Fluent-bit’s internal I/O stack.

Choosing option 2 does imply that when an async output plugin returns:

![State machine](https://raw.githubusercontent.com/hencrice/fluent-bit/rustPlugin/plugins/out_rust_stdout/option2.png)

1. FLB_OK, it might not have successfully flushed the log records to the final destination. Rather it means the plugin has correctly accepted this record and will try to flush it later.
2. FLB_ERROR: The log record is invalid.
3. FLB_RETRY: The log record is valid. However, the plugin’s is too busy now to accept it.

Assuming in option 2, the plugin’s event loop never drops record but instead doing infinite retries while buffering incoming records to a certain point, then it starts returning FLB_RETRY. In that case, the only difference between option 1 and option 2 is the number of event loops involved.

**Pros of option 2:**

1. The plugin controls its own buffering/retry behavior
    1. For example, we might be able to introduce the concept of log level into the Cloudwatch plugin such that critical error are retried forever while warnings can be dropped after 2 retries.
2. Having a separate event loop in the plugin does not prevent us from putting back pressure onto fluent-bit’s own event loop. We just use it implicitly by returning FLB_RETRY.
3. We still have the option to integrate with Fluent-bit event loop later.

**Cons of option 2:**

1. More responsibility on the plugin authors
2. The semantics of FLB_OK, FLB_RETRY, FLB_ERROR changed. However, this can already happen in the current Go plugin model if you write an async Go plugin.
3. At least one separate thread is needed to run the event loop. However, our target customers run Fluent-bit on servers, so don’t think it’s the biggest concern.

### What about arbitrary Rust code/libraries? How will they work with the rest of the C codebase?

rust-bindgen generates Rust FFI code based on given C header files. But there’s an opposite tool called [cbindgen](https://github.com/eqrion/cbindgen) that generates C header files based on Rust struct & function definitions. This means that we can write a Rust library, generate C header files so that all its functionalities are available to the rest of the C code. Or we can import an existing Rust library, write bindings for the parts we need and use it like a C library in the rest of the code.

More importantly, majority of the functionalities exposed through this mechanism should be doable in safe Rust, which provides guarantees on memory & thread safety.

The library will eventually be compiled and statically link with the rest of the C codebase, just like a normal C library.

## Testing

I’ve successfully built a fluent-bit executable that statically linked to the prototype Rust plugin and ran it as a logging sidecar of an nginx container. Docker compose file as follows:

```
version: "3.7"
services:
    nginx:
        image: nginx:1.17.8
        ports:
            - "8080:80"
        # logging configuration docs: https://docs.docker.com/config/containers/logging/fluentd/
        logging:
            driver: fluentd
            options:
                fluentd-async-connect: "true" # buffer messages until connection is established to the fluent-bit sidecar
                # tag: docker.{{.ID}}
    fluentbit:
        image: custom-fluent-bit-exec:latest
        command: /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluent.conf
        volumes:
            - ./fluent-bit.conf:/fluent-bit/etc/fluent.conf
        ports:
            - "24224:24224"
```

Note the lack of any additional shared library when we launch fluent-bit. This is because the Rust plugin is statically linked with the fluent-bit executable. Content of fluent.conf as follows:

```
[SERVICE]
    Flush        1
    Log_level    Debug

[INPUT]
    Name              forward
    Listen            0.0.0.0
    Port              24224
    Buffer_Chunk_Size 32KB
    Buffer_Max_Size   64KB

[OUTPUT]
    Name   rust_stdout
    Match  *
```

## FAQ

1. Will the size of the binary be a concern if we introduce Rust code? (the following data is based on a **debug build.** Both numbers are likely to decrease when we switch to a release build)
    1. For the fluent-bit binary that contains the PoC Rust stdout plugin, the size is 21MB.
    2. For the fluent-bit binary that does not contain the PoC Rust plugin, the size is  15MB.
2. If we adopt Rust. What should be written in Rust and what should be written in C?
    1. The answer is always “it depends”. If we are changing a small portion of code inside an intertwined, battle-tested C portion, then I think it makes more sense to write in C. For new functionalities, it makes more sense to write in Rust. However, the beauty of Rust FFI is you can do it incrementally: Write something in C first, replace it with Rust later when the need for security comes or vice versa.

# Alternatives Tried & lesson learned

Troubles that I ran into:
1. when the Rust plugin was built as a shared library. Difference in struct definition (caused by the flags provided to cmake) when compiling the shared library and the fluent-bit executable can cause problems. The symptom often manifests as weirdly-long address when a pointer is printed out + arbitrary field in the struct is set to null.
2. when the Rust plugin was built as a shared library, it needs fluent-bit-static because every needs to be resolved at link time in order to produce the final .so file. So when calling flb_output_return_non_inline, it references the global flb_thread_key variable in the static library instead of the one set by the fluent-bit executable when it starts up. This means that
when the Rust plugin tried to retrieve the thread-specific data (i.e. the task variable) using pthread_getspecific, it always got back some invalid blob of memory.
3. static library can have declared but undefined symbols: https://www.geeksforgeeks.org/understanding-extern-keyword-in-c/. So the apparent cyclic dependency between a plugin and fluent-bit-static library is not needed when building a Rust plugin
4. Integrating external project into an existing C/C++ project that uses cmake.
5. The way fluent-bit "registers" plugins is inherently unsafe (i.e. globally mutable struct variables) and requires special care from the programmer not to accidentally mutate it, which causes a lot of trouble when wrangling with the Rust compiler
6. Right now the registration structure in Rust looks pretty ugly and lengthy.
7. no space left on device (Docker for Mac) https://github.com/maxheld83/ghactions/issues/240

# Appendix

1. Memory safety:
    1. https://hacks.mozilla.org/2019/01/fearless-security-memory-safety/
    2. http://www.pl-enthusiast.net/2014/07/21/memory-safety/
2. Unsafe Rust:
    1. https://doc.rust-lang.org/nomicon/