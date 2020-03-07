#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub type flb_sds_t = *const ::std::os::raw::c_char;

// when build.rs includes the following 3 lines:
// .whitelist_type("flb_input_plugin")
// .whitelist_type("flb_filter_plugin")
// .whitelist_type("flb_output_plugin")
// the following FFI bindings would be generated.
// They are then adapted by:
// 1. remove the unsafe keyword from all the cb_* functions, such as
//    cb_init, cb_pre_run, cb_flush, cb_collect, cb_exit, ......). The
//    main reason for doing so is because the entire purpose of the Rust
//    plugin is to implement those cb_* function as safe Rust (or at least
//    keep the unsafe portion in them as small as possible). Marking the
//    entire functions as unsafe defeats the purpose.
// 2. change all size_t to usize
// 3. change all *mut ::std::os::raw::c_char to *const ::std::os::raw::c_char
// 4. change *mut flb_config_map to *const flb_config_map
// 5. change *mut flb_uri to *const flb_uri
//      https://www.geeksforgeeks.org/function-overloading-and-const-functions/
// 6. [optional] rename the arguments of all the cb_* functions so that
//    it's easier to read
#[repr(C)]
pub struct flb_rust_stdout {
    pub out_format: ::std::os::raw::c_int,
    pub json_date_format: ::std::os::raw::c_int,
    pub json_date_key: flb_sds_t,
    pub ins: *mut flb_output_instance,
}

#[test]
fn bindgen_test_layout_flb_rust_stdout() {
    assert_eq!(
        ::std::mem::size_of::<flb_rust_stdout>(),
        24usize,
        concat!("Size of: ", stringify!(flb_rust_stdout))
    );
    assert_eq!(
        ::std::mem::align_of::<flb_rust_stdout>(),
        8usize,
        concat!("Alignment of ", stringify!(flb_rust_stdout))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_rust_stdout>())).out_format as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_rust_stdout),
            "::",
            stringify!(out_format)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_rust_stdout>())).json_date_format as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_rust_stdout),
            "::",
            stringify!(json_date_format)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_rust_stdout>())).json_date_key as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_rust_stdout),
            "::",
            stringify!(json_date_key)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_rust_stdout>())).ins as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_rust_stdout),
            "::",
            stringify!(ins)
        )
    );
}


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

#[test]
fn bindgen_test_layout_flb_net_host() {
    assert_eq!(
        ::std::mem::size_of::<flb_net_host>(),
        48usize,
        concat!("Size of: ", stringify!(flb_net_host))
    );
    assert_eq!(
        ::std::mem::align_of::<flb_net_host>(),
        8usize,
        concat!("Alignment of ", stringify!(flb_net_host))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_net_host>())).ipv6 as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_net_host),
            "::",
            stringify!(ipv6)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_net_host>())).address as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_net_host),
            "::",
            stringify!(address)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_net_host>())).port as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_net_host),
            "::",
            stringify!(port)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_net_host>())).name as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_net_host),
            "::",
            stringify!(name)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_net_host>())).listen as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_net_host),
            "::",
            stringify!(listen)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_net_host>())).uri as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_net_host),
            "::",
            stringify!(uri)
        )
    );
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct flb_input_plugin {
    pub flags: ::std::os::raw::c_int,
    pub name: *const ::std::os::raw::c_char,
    pub description: *const ::std::os::raw::c_char,
    pub config_map: *const flb_config_map,
    pub cb_init: ::std::option::Option<
        extern "C" fn(
            arg1: *mut flb_input_instance,
            arg2: *mut flb_config,
            arg3: *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub cb_pre_run: ::std::option::Option<
        extern "C" fn(
            arg1: *mut flb_input_instance,
            arg2: *mut flb_config,
            arg3: *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub cb_collect: ::std::option::Option<
        extern "C" fn(
            arg1: *mut flb_input_instance,
            arg2: *mut flb_config,
            arg3: *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub cb_flush_buf: ::std::option::Option<
        extern "C" fn(
            arg1: *mut ::std::os::raw::c_void,
            arg2: *mut usize,
        ) -> *mut ::std::os::raw::c_void,
    >,
    pub cb_flush_end: ::std::option::Option<extern "C" fn(arg1: *mut ::std::os::raw::c_void)>,
    pub cb_pause: ::std::option::Option<
        extern "C" fn(arg1: *mut ::std::os::raw::c_void, arg2: *mut flb_config),
    >,
    pub cb_resume: ::std::option::Option<
        extern "C" fn(arg1: *mut ::std::os::raw::c_void, arg2: *mut flb_config),
    >,
    pub cb_ingest: ::std::option::Option<
        extern "C" fn(
            in_context: *mut ::std::os::raw::c_void,
            arg1: *mut ::std::os::raw::c_void,
            arg2: usize,
        ) -> ::std::os::raw::c_int,
    >,
    pub cb_exit: ::std::option::Option<
        extern "C" fn(
            arg1: *mut ::std::os::raw::c_void,
            arg2: *mut flb_config,
        ) -> ::std::os::raw::c_int,
    >,
    pub instance: *mut ::std::os::raw::c_void,
    pub _head: mk_list,
}
#[test]
fn bindgen_test_layout_flb_input_plugin() {
    assert_eq!(
        ::std::mem::size_of::<flb_input_plugin>(),
        128usize,
        concat!("Size of: ", stringify!(flb_input_plugin))
    );
    assert_eq!(
        ::std::mem::align_of::<flb_input_plugin>(),
        8usize,
        concat!("Alignment of ", stringify!(flb_input_plugin))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).flags as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).name as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(name)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).description as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(description)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).config_map as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(config_map)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).cb_init as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(cb_init)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).cb_pre_run as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(cb_pre_run)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).cb_collect as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(cb_collect)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).cb_flush_buf as *const _ as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(cb_flush_buf)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).cb_flush_end as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(cb_flush_end)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).cb_pause as *const _ as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(cb_pause)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).cb_resume as *const _ as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(cb_resume)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).cb_ingest as *const _ as usize },
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(cb_ingest)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).cb_exit as *const _ as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(cb_exit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>())).instance as *const _ as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(instance)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_input_plugin>()))._head as *const _ as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_input_plugin),
            "::",
            stringify!(_head)
        )
    );
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct flb_filter_plugin {
    pub flags: ::std::os::raw::c_int,
    pub name: *const ::std::os::raw::c_char,
    pub description: *const ::std::os::raw::c_char,
    pub config_map: *const flb_config_map,
    pub cb_init: ::std::option::Option<
        extern "C" fn(
            arg1: *mut flb_filter_instance,
            arg2: *mut flb_config,
            arg3: *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub cb_filter: ::std::option::Option<
        extern "C" fn(
            arg1: *const ::std::os::raw::c_void,
            arg2: usize,
            arg3: *const ::std::os::raw::c_char,
            arg4: ::std::os::raw::c_int,
            arg5: *mut *mut ::std::os::raw::c_void,
            arg6: *mut usize,
            arg7: *mut flb_filter_instance,
            arg8: *mut ::std::os::raw::c_void,
            arg9: *mut flb_config,
        ) -> ::std::os::raw::c_int,
    >,
    pub cb_exit: ::std::option::Option<
        extern "C" fn(
            arg1: *mut ::std::os::raw::c_void,
            arg2: *mut flb_config,
        ) -> ::std::os::raw::c_int,
    >,
    pub _head: mk_list,
}
#[test]
fn bindgen_test_layout_flb_filter_plugin() {
    assert_eq!(
        ::std::mem::size_of::<flb_filter_plugin>(),
        72usize,
        concat!("Size of: ", stringify!(flb_filter_plugin))
    );
    assert_eq!(
        ::std::mem::align_of::<flb_filter_plugin>(),
        8usize,
        concat!("Alignment of ", stringify!(flb_filter_plugin))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_filter_plugin>())).flags as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_filter_plugin),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_filter_plugin>())).name as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_filter_plugin),
            "::",
            stringify!(name)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_filter_plugin>())).description as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_filter_plugin),
            "::",
            stringify!(description)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_filter_plugin>())).config_map as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_filter_plugin),
            "::",
            stringify!(config_map)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_filter_plugin>())).cb_init as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_filter_plugin),
            "::",
            stringify!(cb_init)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_filter_plugin>())).cb_filter as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_filter_plugin),
            "::",
            stringify!(cb_filter)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_filter_plugin>())).cb_exit as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_filter_plugin),
            "::",
            stringify!(cb_exit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_filter_plugin>()))._head as *const _ as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_filter_plugin),
            "::",
            stringify!(_head)
        )
    );
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct flb_output_plugin {
    pub type_: ::std::os::raw::c_int,
    pub proxy: *mut ::std::os::raw::c_void,
    pub flags: ::std::os::raw::c_int,
    pub name: *const ::std::os::raw::c_char,
    pub description: *const ::std::os::raw::c_char,
    pub config_map: *const flb_config_map,
    pub host: flb_net_host,
    pub cb_init: ::std::option::Option<
        extern "C" fn(
            arg1: *mut flb_output_instance,
            arg2: *mut flb_config,
            arg3: *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub cb_pre_run: ::std::option::Option<
        extern "C" fn(
            arg1: *mut ::std::os::raw::c_void,
            arg2: *mut flb_config,
        ) -> ::std::os::raw::c_int,
    >,
    pub cb_flush: ::std::option::Option<
        extern "C" fn(
            arg1: *const ::std::os::raw::c_void,
            arg2: usize,
            arg3: *const ::std::os::raw::c_char,
            arg4: ::std::os::raw::c_int,
            arg5: *mut flb_input_instance,
            arg6: *mut ::std::os::raw::c_void,
            arg7: *mut flb_config,
        ),
    >,
    pub cb_exit: ::std::option::Option<
        extern "C" fn(
            arg1: *mut ::std::os::raw::c_void,
            arg2: *mut flb_config,
        ) -> ::std::os::raw::c_int,
    >,
    pub _head: mk_list,
}

#[test]
fn bindgen_test_layout_flb_output_plugin() {
    assert_eq!(
        ::std::mem::size_of::<flb_output_plugin>(),
        144usize,
        concat!("Size of: ", stringify!(flb_output_plugin))
    );
    assert_eq!(
        ::std::mem::align_of::<flb_output_plugin>(),
        8usize,
        concat!("Alignment of ", stringify!(flb_output_plugin))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).proxy as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(proxy)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).flags as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).name as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(name)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).description as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(description)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).config_map as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(config_map)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).host as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(host)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).cb_init as *const _ as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(cb_init)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).cb_pre_run as *const _ as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(cb_pre_run)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).cb_flush as *const _ as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(cb_flush)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>())).cb_exit as *const _ as usize },
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(cb_exit)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<flb_output_plugin>()))._head as *const _ as usize },
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(flb_output_plugin),
            "::",
            stringify!(_head)
        )
    );
}

// The way fluent-bit C plugin "registers" themselves through
// globally mutable struct variable is inherently unsafe. So
// we have to convince the Rust plugin that the flb_XXXXX_plugin
// types are thread-safe.
unsafe impl Sync for flb_input_plugin {}
unsafe impl Sync for flb_filter_plugin {}
unsafe impl Sync for flb_output_plugin {}

// TODO: Define common Fluent-bit constants