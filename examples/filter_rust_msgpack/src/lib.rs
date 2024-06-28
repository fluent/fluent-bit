// Import pure and fast msgpack library written in Rust
use rmp_serde::Serializer;
use serde::{Deserialize, Serialize};
use rmpv::Value;

// Import chrono library to handle time related operation conveniently
use chrono::{TimeZone, Utc};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::io::Write;
use std::os::raw::c_char;
use std::slice;
use std::str;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct FilteredLog {
    message: String,
    time: String,
    tag: String,
    original: BTreeMap<String, String>,
    lang: String,
}

#[inline]
fn value_to_string(val: &Value) -> String {
    if val.is_str() {
        let into = match val {
            Value::String(s) => s.clone().into_str(),
            _ => unreachable!()
        };
        match into {
            Some(i) => i.to_string(),
            None => "".to_string(),
        }
    } else {
        format!("{}", val)
    }
}

#[no_mangle]
pub extern "C" fn rust_filter_msgpack(tag: *const c_char, tag_len: u32, time_sec: u32, time_nsec: u32, record: *const c_char, record_len: u32) -> *const u8 {
    let slice_tag: &[u8] = unsafe { slice::from_raw_parts(tag as *const u8, tag_len as usize) };
    let mut vt: Vec<u8> = Vec::new();
    vt.write(slice_tag).expect("Unable to write");
    let vtag = str::from_utf8(&vt).unwrap();
    let slice_record: &[u8] =
        unsafe { slice::from_raw_parts(record as *const u8, record_len as usize) };
    let de = rmpv::decode::read_value(&mut Cursor::new(slice_record)).unwrap();

    let mut map = BTreeMap::new();

    let binding = de.as_map().unwrap();
    let size = binding.len();

    // Create BTreeMap to handle collection operations easily
    for i in 0..size {
        let (k, v) = &binding[i];
        let key = value_to_string(k);
        let value = value_to_string(v);
        map.insert(key, value);
    }

    map.insert("platform".to_string(), "wasm".to_string());

    let dt = Utc.timestamp_opt(time_sec as i64, time_nsec).unwrap();
    let time = dt.format("%Y-%m-%dT%H:%M:%S.%9f %z").to_string();
    let mut buf = Vec::new();
    let msg = match map.get("message") {
        Some(m) => m.to_string(),
        None => "None".to_string(),
    };
    let val = FilteredLog {
        message: msg,
        time: format!("{}", time),
        tag: vtag.to_owned(),
        original: map,
        lang: "Rust".to_string(),
    };

    let mut se = Serializer::new(&mut buf).with_struct_map();
    val.serialize(&mut se).unwrap();
    buf.as_ptr()
}
