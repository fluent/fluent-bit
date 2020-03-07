extern crate rmp_serde as rmps;
extern crate serde;

use {
    std::{
        collections::HashMap,
        error,
        ffi::c_void,
        mem,
        os::raw::{c_char, c_int},
        ptr,
    },
};

use serde::{Deserialize, Serialize};

use rust_binding;

// Rust's convention is to use CAP_SNAKE for statics. However,
// the fluent-bit codebase expects plugin name to conform to certain
// convention:
// https://github.com/fluent/fluent-bit/blob/baff15640e97ac46d457aab011e9103f2dca53ce/plugins/CMakeLists.txt#L61
// So we export the symbol as a different name below.
#[export_name = "out_rust_stdout_plugin"]
pub static mut OUT_STDOUT2_PLUGIN: rust_binding::flb_output_plugin =
    rust_binding::flb_output_plugin {
        // TODO: Define enum for plugin types
        // https://github.com/fluent/fluent-bit/blob/e6506b7b5364c77bec186d94e51c4b3b51e6fbac/include/fluent-bit/flb_plugin.h#L28
        type_: 1,
        proxy: ptr::null_mut(),
        flags: 0,
        // http://jakegoulding.com/rust-ffi-omnibus/string_return/
        // https://stackoverflow.com/questions/53611161/how-do-i-expose-a-compile-time-generated-static-c-string-through-ffi
        name: "rust_stdout\0".as_ptr() as *const c_char,
        description: "experiement\0".as_ptr() as *const c_char,
        // http://jakegoulding.com/rust-ffi-omnibus/
        // https://medium.com/jim-fleming/complex-types-with-rust-s-ffi-315d14619479
        // https://s3.amazonaws.com/temp.michaelfbryan.com/arrays/index.html
        // https://github.com/fluent/fluent-bit/blob/master/src/flb_output.c#L628
        config_map: [
            rust_binding::flb_config_map {
                type_: 0,
                name: "format\0".as_ptr() as *const c_char,
                def_value: ptr::null(),
                flags: 0,
                set_property: 0,
                offset: 0,
                desc: ptr::null(),
                // https://github.com/fluent/fluent-bit/blob/46c322c0cc8c09908c25f8356ea7bf8b848ff6b2/src/flb_config_map.c#L287
                // looks like we always allocated new memory, so it might be ok to leave the
                // some fields uninitialized
                value: rust_binding::flb_config_map_val {
                    val: rust_binding::flb_config_map_val__bindgen_ty_1 {
                        i_num: rust_binding::__BindgenUnionField::new(),
                        boolean: rust_binding::__BindgenUnionField::new(),
                        d_num: rust_binding::__BindgenUnionField::new(),
                        s_num: rust_binding::__BindgenUnionField::new(),
                        str: rust_binding::__BindgenUnionField::new(),
                        list: rust_binding::__BindgenUnionField::new(),
                        bindgen_union_field: 0,
                    },
                    mult: ptr::null_mut(),
                    _head: rust_binding::mk_list {
                        prev: ptr::null_mut(),
                        next: ptr::null_mut(),
                    },
                },
                _head: rust_binding::mk_list {
                    prev: ptr::null_mut(),
                    next: ptr::null_mut(),
                },
            },
            rust_binding::flb_config_map {
                type_: 0,
                name: "json_date_format\0".as_ptr() as *const c_char,
                def_value: ptr::null(),
                flags: 0,
                set_property: 0,
                offset: 0,
                desc: ptr::null(),
                value: rust_binding::flb_config_map_val {
                    val: rust_binding::flb_config_map_val__bindgen_ty_1 {
                        i_num: rust_binding::__BindgenUnionField::new(),
                        boolean: rust_binding::__BindgenUnionField::new(),
                        d_num: rust_binding::__BindgenUnionField::new(),
                        s_num: rust_binding::__BindgenUnionField::new(),
                        str: rust_binding::__BindgenUnionField::new(),
                        list: rust_binding::__BindgenUnionField::new(),
                        bindgen_union_field: 0,
                    },
                    mult: ptr::null_mut(),
                    _head: rust_binding::mk_list {
                        prev: ptr::null_mut(),
                        next: ptr::null_mut(),
                    },
                },
                _head: rust_binding::mk_list {
                    prev: ptr::null_mut(),
                    next: ptr::null_mut(),
                },
            },
            rust_binding::flb_config_map {
                type_: 0,
                name: "json_date_format\0".as_ptr() as *const c_char,
                def_value: "date\0".as_ptr() as *const c_char,
                flags: 0,
                set_property: 1,
                // calculate offset same as https://github.com/fluent/fluent-bit/blob/e6506b7b5364c77bec186d94e51c4b3b51e6fbac/plugins/out_stdout/stdout.c#L171
                // https://crates.io/crates/memoffset
                // TODO: need to figure out how to do this
                offset: 20,
                desc: ptr::null(),
                value: rust_binding::flb_config_map_val {
                    val: rust_binding::flb_config_map_val__bindgen_ty_1 {
                        i_num: rust_binding::__BindgenUnionField::new(),
                        boolean: rust_binding::__BindgenUnionField::new(),
                        d_num: rust_binding::__BindgenUnionField::new(),
                        s_num: rust_binding::__BindgenUnionField::new(),
                        str: rust_binding::__BindgenUnionField::new(),
                        list: rust_binding::__BindgenUnionField::new(),
                        bindgen_union_field: 0,
                    },
                    mult: ptr::null_mut(),
                    _head: rust_binding::mk_list {
                        prev: ptr::null_mut(),
                        next: ptr::null_mut(),
                    },
                },
                _head: rust_binding::mk_list {
                    prev: ptr::null_mut(),
                    next: ptr::null_mut(),
                },
            },
            // EOF represented by 0 for type_ and null for name:
            // https://github.com/fluent/fluent-bit/blob/5b08b2073cb86b34fa2419be55078a45fdf37236/src/flb_config_map.c#L274
            rust_binding::flb_config_map {
                type_: 0,
                name: ptr::null(),
                def_value: ptr::null(),
                flags: 0,
                set_property: 0,
                offset: 0,
                desc: ptr::null(),
                value: rust_binding::flb_config_map_val {
                    val: rust_binding::flb_config_map_val__bindgen_ty_1 {
                        i_num: rust_binding::__BindgenUnionField::new(),
                        boolean: rust_binding::__BindgenUnionField::new(),
                        d_num: rust_binding::__BindgenUnionField::new(),
                        s_num: rust_binding::__BindgenUnionField::new(),
                        str: rust_binding::__BindgenUnionField::new(),
                        list: rust_binding::__BindgenUnionField::new(),
                        bindgen_union_field: 0,
                    },
                    mult: ptr::null_mut(),
                    _head: rust_binding::mk_list {
                        prev: ptr::null_mut(),
                        next: ptr::null_mut(),
                    },
                },
                _head: rust_binding::mk_list {
                    prev: ptr::null_mut(),
                    next: ptr::null_mut(),
                },
            },
        ]
        .as_ptr(),
        host: rust_binding::flb_net_host {
            ipv6: 0,
            address: ptr::null(),
            port: 0,
            name: ptr::null(),
            listen: ptr::null(),
            uri: ptr::null(),
        },
        // TODO: figure out whther I need to deal with cb_pre_run
        cb_pre_run: None,
        // From https://github.com/fluent/fluent-bit/blob/e6506b7b5364c77bec186d94e51c4b3b51e6fbac/src/flb_plugin.c#L248
        // seems like it will be allocated so no need to allocate here
        _head: rust_binding::mk_list {
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
        },
        cb_init: Some(plugin_init),
        cb_flush: Some(plugin_flush),
        cb_exit: Some(plugin_exit),
    };

#[no_mangle]
extern "C" fn plugin_init(
    ins: *mut rust_binding::flb_output_instance,
    config: *mut rust_binding::flb_config,
    data: *mut c_void,
) -> c_int {
    unsafe {
        // TODO: [MemoryManagement] Need to use Box for the following to allocate it on heap?
        // https://stackoverflow.com/questions/28278213/how-to-lend-a-rust-object-to-c-code-for-an-arbitrary-lifetime
        let mut ctx = Box::new(mem::zeroed::<rust_binding::flb_rust_stdout>());
        ctx.ins = ins;

        // One potential solution to access #define constant in C through Rust FFI:
        // https://stackoverflow.com/questions/21485655/how-do-i-use-c-preprocessor-macros-with-rusts-ffi
        ctx.out_format = 0;
        let fmt_ptr =
            rust_binding::flb_output_get_property("format".as_ptr() as *const c_char, ins);
        // https://doc.rust-lang.org/std/primitive.pointer.html#method.as_ref
        if fmt_ptr.as_ref().is_some() {
            let ret = rust_binding::flb_pack_to_json_format_type(fmt_ptr);
            if ret == -1 {
                // TODO: use fluent-bit's logger? flb_plg_error is a macro defined
                // at https://github.com/fluent/fluent-bit/blob/master/include/fluent-bit/flb_output_plugin.h#L28
                // flb_plg_error(ctx->ins, "invalid json_date_format '%s'. "
                //              "Using 'double' type", tmp);
                println!("flb_pack_to_json_format_type error")
            } else {
                ctx.out_format = ret;
            }
        }

        ctx.json_date_format = 0;
        let date_fmt_ptr = rust_binding::flb_output_get_property(
            "json_date_format".as_ptr() as *const c_char,
            ins,
        );
        if date_fmt_ptr.as_ref().is_some() {
            let ret = rust_binding::flb_pack_to_json_date_type(date_fmt_ptr);
            if ret == -1 {
                // TODO: use fluent-bit's logger? flb_plg_error is a macro defined
                // at https://github.com/fluent/fluent-bit/blob/master/include/fluent-bit/flb_output_plugin.h#L28
                // flb_plg_error(ctx->ins, "invalid json_date_format '%s'. "
                // "Using 'double' type", tmp);
                println!("flb_pack_to_json_date_type error");
            } else {
                ctx.json_date_format = ret;
            }
        }

        // https://doc.rust-lang.org/std/ffi/enum.c_void.html
        // https://stackoverflow.com/questions/24191249/working-with-c-void-in-an-ffi
        // https://users.rust-lang.org/t/semantics-of-mut--/5514
        let ctx_ptr: *mut c_void = Box::into_raw(ctx) as *mut c_void;
        // https://github.com/rust-lang/rust/issues/61820
        // https://stackoverflow.com/questions/17081131/how-can-a-shared-library-so-call-a-function-that-is-implemented-in-its-loadin
        // https://stackoverflow.com/questions/36692315/what-exactly-does-rdynamic-do-and-when-exactly-is-it-needed
        // https://stackoverflow.com/questions/5555632/can-gcc-not-complain-about-undefined-references
        // this is how fluent-bit compiles its built-in plugins:
        // https://github.com/fluent/fluent-bit/blob/master/plugins/CMakeLists.txt#L110
        // https://github.com/fluent/fluent-bit/blob/master/plugins/out_stdout/CMakeLists.txt
        let ret = rust_binding::flb_config_map_set(
            &mut (*ins).properties,
            (*ins).config_map,
            ctx_ptr,
        );
        if ret == -1 {
            return ret;
        }

        rust_binding::flb_output_set_context(ins, ctx_ptr);
    }

    0
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct Record {
    // https://docs.fluentbit.io/manual/development/ingest_records_manually
    timestamp: u32,
    record: HashMap<String, String>,
}

// #[derive(Debug, PartialEq, Deserialize, Serialize)]
// struct CPURecord {
//     cpu_p: f32,
//     user_p: f32,
//     system_p: f32,
// }

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
    // https://www.reddit.com/r/rust/comments/9wk0jy/free_memory_allocated_from_c_through_ffi/
    // https://users.rust-lang.org/t/c-ffi-memory-leak-take-ownership-of-allocated-memory-in-c-c/24337/3
    // https://hacks.mozilla.org/2019/04/crossing-the-rust-ffi-frontier-with-protocol-buffers/

    // https://github.com/fluent/fluent-bit-go/blob/master/output/decoder.go#L57
    // https://github.com/aws/amazon-kinesis-firehose-for-fluent-bit/blob/6ca31170fc03aa8081255de927a87156d787ce14/fluent-bit-firehose.go#L105
    // https://github.com/fluent/fluent-bit-go/blob/master/output/decoder.go#L70
    // just unpack the data, which is in msgpack format,
    // generated from https://docs.fluentbit.io/manual/input/cpu
    // and print.

    // https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html
    // https://stackoverflow.com/questions/27150652/how-can-i-get-an-array-or-a-slice-from-a-raw-pointer
    let msg_pack_raw_data: &[u8] = unsafe {
        // TODO: verify correct lifetime of the returned variable:
        // https://stackoverflow.com/questions/33305573/why-is-the-lifetime-important-for-slicefrom-raw-parts
        std::slice::from_raw_parts(data as *const u8, bytes)
    };

    // https://docs.rs/rmp-serde/0.14.3/rmp_serde/
    let value: Result<Record, rmps::decode::Error> = rmps::from_slice(msg_pack_raw_data);
    match value {
        Ok(v) => {
            println!("ok from msg pack: {:#?}", v);
        }
        Err(e) => println!("err returned from msg pack: {}", e),
    }

    unsafe {
        rust_binding::flb_output_return_non_inline(1);
    }
}

#[no_mangle]
extern "C" fn plugin_exit(data: *mut c_void, config: *mut rust_binding::flb_config) -> c_int {
    // TODO: [MemoryManagement] Do we need to free the data argument just like the
    // C stdout output plugin?
    // https://stackoverflow.com/questions/38289355/drop-a-rust-void-pointer-stored-in-an-ffi
    // https://stackoverflow.com/questions/50107792/what-is-the-better-way-to-wrap-a-ffi-struct-that-owns-or-borrows-data
    // [2nd solution?] https://stackoverflow.com/questions/28278213/how-to-lend-a-rust-object-to-c-code-for-an-arbitrary-lifetime
    if !data.is_null() {
        unsafe {
            Box::from_raw(data as *mut rust_binding::flb_rust_stdout); // Rust auto-drops it at the end of this function
        }
    }
    0
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
