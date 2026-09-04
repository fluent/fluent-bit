use databricks_zerobus_ingest_sdk::zeroparser::MessageRegistry;
use prost::Message;
use prost_types::{DescriptorProto, FileDescriptorSet};

pub const E2E_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/e2e_descriptor_set.bin"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoVersion {
    Proto2,
    Proto3,
}

impl ProtoVersion {
    fn package(&self) -> &'static str {
        match self {
            ProtoVersion::Proto2 => "zeroparser.e2e.proto2",
            ProtoVersion::Proto3 => "zeroparser.e2e.proto3",
        }
    }
}

pub fn load_descriptor_set(version: ProtoVersion) -> FileDescriptorSet {
    let mut set = FileDescriptorSet::decode(E2E_DESCRIPTOR_SET).expect("decode descriptor file");
    set.file
        .retain(|f| f.package.as_deref() == Some(version.package()));
    set
}

fn find_message_and_file<'a>(
    file_desc_set: &'a FileDescriptorSet,
    package: &str,
    message_name: &str,
) -> (&'a DescriptorProto, &'a prost_types::FileDescriptorProto) {
    for file in &file_desc_set.file {
        if file.package.as_deref() != Some(package) {
            continue;
        }
        for msg_desc in &file.message_type {
            if msg_desc.name.as_deref() == Some(message_name) {
                return (msg_desc, file);
            }
        }
    }
    panic!("message {package}.{message_name} not found in descriptor set");
}

pub fn get_message_descriptor(
    file_desc_set: &FileDescriptorSet,
    message_name: &str,
) -> DescriptorProto {
    for file in &file_desc_set.file {
        for msg_desc in &file.message_type {
            if msg_desc.name.as_deref() == Some(message_name) {
                return msg_desc.clone();
            }
        }
    }
    panic!("message {message_name} not found in descriptor set");
}

pub fn create_registry_for_version(version: ProtoVersion, message_name: &str) -> MessageRegistry {
    let file_desc_set = load_descriptor_set(version);
    let (msg_desc, file) = find_message_and_file(&file_desc_set, version.package(), message_name);
    let mut descriptor = msg_desc.clone();
    descriptor.name = Some(format!(
        "{}.{message_name}",
        file.package.as_deref().unwrap_or("")
    ));
    MessageRegistry::from_descriptor(&descriptor)
}

pub fn encode_message_for_version<M: Message>(
    version: ProtoVersion,
    msg: &M,
    message_name: &str,
) -> (Vec<u8>, MessageRegistry) {
    let registry = create_registry_for_version(version, message_name);
    let mut buf = Vec::new();
    msg.encode(&mut buf).unwrap();
    (buf, registry)
}

pub mod all_types_fields {
    pub mod proto2 {
        pub const F_INT32: i32 = 29;
        pub const F_INT64: i32 = 11;
        pub const F_UINT32: i32 = 33;
        pub const F_UINT64: i32 = 2;
        pub const F_SINT32: i32 = 24;
        pub const F_SINT64: i32 = 15;
        pub const F_FIXED32: i32 = 31;
        pub const F_FIXED64: i32 = 5;
        pub const F_SFIXED32: i32 = 22;
        pub const F_SFIXED64: i32 = 9;
        pub const F_FLOAT: i32 = 27;
        pub const F_DOUBLE: i32 = 3;
        pub const F_BOOL: i32 = 19;
        pub const F_STRING: i32 = 12;
        pub const F_BYTES: i32 = 26;
        pub const F_ENUM: i32 = 8;
        pub const F_REQUIRED: i32 = 34;
        pub const F_DEFAULT_INT: i32 = 14;
        pub const F_DEFAULT_STRING: i32 = 20;
        pub const F_DEFAULT_BOOL: i32 = 13;
        pub const F_NESTED: i32 = 4;
        pub const F_DEEPLY_NESTED: i32 = 16;
        pub const F_REPEATED_INT32: i32 = 10;
        pub const F_REPEATED_STRING: i32 = 21;
        pub const F_REPEATED_PACKED: i32 = 6;
        pub const F_REPEATED_UNPACKED: i32 = 23;
        pub const F_REPEATED_MESSAGE: i32 = 1;
        pub const F_MAP_INT_STRING: i32 = 32;
        pub const F_MAP_STRING_STRING: i32 = 28;
        pub const F_MAP_STRING_MESSAGE: i32 = 17;
        pub const F_ONEOF_INT: i32 = 25;
        pub const F_ONEOF_STRING: i32 = 30;
        pub const F_ONEOF_MESSAGE: i32 = 250;
        pub const F_REPEATED_ENUM: i32 = 175;
        pub const F_LARGE_FIELD_150: i32 = 301;
        pub const F_LARGE_FIELD_200: i32 = 150;
        pub const F_LARGE_FIELD_300: i32 = 200;
    }
    pub mod proto3 {
        pub const F_OPTIONAL_INT32: i32 = 34;
        pub const F_OPTIONAL_STRING: i32 = 14;
        pub const F_OPTIONAL_BOOL: i32 = 20;
    }
}

pub mod complex_nested_fields {
    pub const ID: i32 = 29;
    pub const NAME: i32 = 11;
    pub const INNER: i32 = 33;
    pub const INT_LIST: i32 = 2;
    pub const STRING_LIST: i32 = 24;
    pub const BOOL_LIST: i32 = 15;
    pub const INNER_LIST: i32 = 31;
    pub const STRING_TO_INT: i32 = 5;
    pub const INT_TO_STRING: i32 = 22;
    pub const STRING_TO_MESSAGE: i32 = 9;
    pub const DATA_WITH_MAPS: i32 = 27;
    pub const ITEMS: i32 = 3;
    pub const TREE: i32 = 19;

    pub mod inner_data {
        pub const VALUE: i32 = 29;
        pub const DATA: i32 = 11;
        pub const NUMBERS: i32 = 33;
    }

    pub mod data_with_maps {
        pub const LABEL: i32 = 29;
        pub const PROPERTIES: i32 = 11;
        pub const INDICES: i32 = 33;
    }

    pub mod complex_item {
        pub const ITEM_ID: i32 = 29;
        pub const TAGS: i32 = 11;
        pub const ATTRIBUTES: i32 = 33;
    }

    pub mod tree_node {
        pub const VALUE: i32 = 29;
        pub const LABEL: i32 = 11;
        pub const CHILDREN: i32 = 33;
        pub const LEFT: i32 = 2;
        pub const RIGHT: i32 = 24;
    }
}

pub mod nested_message_fields {
    pub const NESTED_ID: i32 = 18;
    pub const NESTED_NAME: i32 = 7;
}

pub mod deeply_nested_message_fields {
    pub const DEEP_ID: i32 = 18;
    pub const NESTED: i32 = 7;
}

pub mod supported_types_fields {
    pub const APPROVED: i32 = 29;
    pub const DAY_NUM: i32 = 11;
    pub const COST: i32 = 33;
    pub const DESCRIPTION: i32 = 2;
    pub const DISCOUNT: i32 = 24;
    pub const COST_WITH_DISCOUNT: i32 = 15;
    pub const PHOTO: i32 = 31;
    pub const TAGS: i32 = 5;
    pub const METADATA: i32 = 22;
}

pub fn field_num(version: ProtoVersion, field_name: &str) -> i32 {
    use all_types_fields::{proto2, proto3};

    match (version, field_name) {
        (_, "f_int32") => proto2::F_INT32,
        (_, "f_int64") => proto2::F_INT64,
        (_, "f_uint32") => proto2::F_UINT32,
        (_, "f_uint64") => proto2::F_UINT64,
        (_, "f_sint32") => proto2::F_SINT32,
        (_, "f_sint64") => proto2::F_SINT64,
        (_, "f_fixed32") => proto2::F_FIXED32,
        (_, "f_fixed64") => proto2::F_FIXED64,
        (_, "f_sfixed32") => proto2::F_SFIXED32,
        (_, "f_sfixed64") => proto2::F_SFIXED64,
        (_, "f_float") => proto2::F_FLOAT,
        (_, "f_double") => proto2::F_DOUBLE,
        (_, "f_bool") => proto2::F_BOOL,
        (_, "f_string") => proto2::F_STRING,
        (_, "f_bytes") => proto2::F_BYTES,
        (_, "f_enum") => proto2::F_ENUM,

        (ProtoVersion::Proto2, "f_required") => proto2::F_REQUIRED,
        (ProtoVersion::Proto2, "f_default_int") => proto2::F_DEFAULT_INT,
        (ProtoVersion::Proto2, "f_default_string") => proto2::F_DEFAULT_STRING,
        (ProtoVersion::Proto2, "f_default_bool") => proto2::F_DEFAULT_BOOL,

        (ProtoVersion::Proto3, "f_optional_int32") => proto3::F_OPTIONAL_INT32,
        (ProtoVersion::Proto3, "f_optional_string") => proto3::F_OPTIONAL_STRING,
        (ProtoVersion::Proto3, "f_optional_bool") => proto3::F_OPTIONAL_BOOL,

        (_, "f_nested") => proto2::F_NESTED,
        (_, "f_deeply_nested") => proto2::F_DEEPLY_NESTED,

        (_, "f_repeated_int32") => proto2::F_REPEATED_INT32,
        (_, "f_repeated_string") => proto2::F_REPEATED_STRING,
        (ProtoVersion::Proto2, "f_repeated_packed") => proto2::F_REPEATED_PACKED,
        (ProtoVersion::Proto2, "f_repeated_unpacked") => proto2::F_REPEATED_UNPACKED,
        (_, "f_repeated_message") => proto2::F_REPEATED_MESSAGE,

        (_, "f_map_int_string") => proto2::F_MAP_INT_STRING,
        (_, "f_map_string_string") => proto2::F_MAP_STRING_STRING,
        (_, "f_map_string_message") => proto2::F_MAP_STRING_MESSAGE,

        (_, "f_oneof_int") => proto2::F_ONEOF_INT,
        (_, "f_oneof_string") => proto2::F_ONEOF_STRING,
        (_, "f_oneof_message") => proto2::F_ONEOF_MESSAGE,

        (_, "f_repeated_enum") => proto2::F_REPEATED_ENUM,

        (_, "f_large_field_150") => proto2::F_LARGE_FIELD_150,
        (_, "f_large_field_200") => proto2::F_LARGE_FIELD_200,
        (_, "f_large_field_300") => proto2::F_LARGE_FIELD_300,

        _ => panic!("Unknown field name '{field_name}' for {version:?}"),
    }
}
