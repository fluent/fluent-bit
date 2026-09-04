use criterion::black_box as bb;
use databricks_zerobus_ingest_sdk::zeroparser::parser::ParsedMessage;
use databricks_zerobus_ingest_sdk::zeroparser::types::FieldValueRef;
use databricks_zerobus_ingest_sdk::zeroparser::MessageRegistry;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, ReflectMessage, Value};
use prost_types::field_descriptor_proto::Type as ProstFieldType;
use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorSet};
use serde_json::Value as JsonValue;

pub const BENCH_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/bench_descriptor_set.bin"));

pub const SAMPLE_DATA_JSON: &str = include_str!("../bench_sample_data.json");

pub mod proto {
    pub mod air_quality {
        include!(concat!(
            env!("OUT_DIR"),
            "/zeroparser.benches.air_quality.rs"
        ));
    }
    pub mod wide_schema {
        include!(concat!(
            env!("OUT_DIR"),
            "/zeroparser.benches.wide_schema.rs"
        ));
    }
    pub mod supported_nullable_types {
        include!(concat!(
            env!("OUT_DIR"),
            "/zeroparser.benches.supported_nullable_types.rs"
        ));
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ProstTypedKind {
    AirQuality,
    SupportedNullableTypes,
    WideSchema,
}

impl ProstTypedKind {
    fn from_name(name: &str) -> Self {
        match name {
            "AirQuality" => Self::AirQuality,
            "SupportedNullableTypes" => Self::SupportedNullableTypes,
            "WideSchema" => Self::WideSchema,
            other => panic!("no prost typed walker for message {other}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldKind {
    Scalar,
    RepeatedScalar,
    RepeatedMessage,
    Map,
}

const LABEL_REPEATED: i32 = 3;

fn classify_field(field: &FieldDescriptorProto, nested: &[DescriptorProto]) -> FieldKind {
    if field.label != Some(LABEL_REPEATED) {
        return FieldKind::Scalar;
    }
    if field.r#type() != ProstFieldType::Message {
        return FieldKind::RepeatedScalar;
    }
    let last = field
        .type_name
        .as_deref()
        .and_then(|n| n.rsplit('.').next())
        .unwrap_or("");
    let is_map = nested
        .iter()
        .find(|n| n.name.as_deref() == Some(last))
        .and_then(|n| n.options.as_ref().and_then(|o| o.map_entry))
        == Some(true);
    if is_map {
        FieldKind::Map
    } else {
        FieldKind::RepeatedMessage
    }
}

/// Pre-classified field numbers; lets the Zeroparser walk dispatch on kind
/// once per scenario instead of per field.
pub struct FieldSet {
    pub scalars: Vec<i32>,
    pub repeated_scalars: Vec<i32>,
    pub repeated_messages: Vec<i32>,
    pub maps: Vec<i32>,
}

impl FieldSet {
    fn from_descriptor(desc: &DescriptorProto) -> Self {
        let mut scalars = Vec::new();
        let mut repeated_scalars = Vec::new();
        let mut repeated_messages = Vec::new();
        let mut maps = Vec::new();
        for f in &desc.field {
            let Some(num) = f.number else { continue };
            match classify_field(f, &desc.nested_type) {
                FieldKind::Scalar => scalars.push(num),
                FieldKind::RepeatedScalar => repeated_scalars.push(num),
                FieldKind::RepeatedMessage => repeated_messages.push(num),
                FieldKind::Map => maps.push(num),
            }
        }
        Self {
            scalars,
            repeated_scalars,
            repeated_messages,
            maps,
        }
    }
}

pub struct BenchmarkConfig {
    pub registry: MessageRegistry,
    pub msg_desc: MessageDescriptor,
    pub fields: FieldSet,
    pub prost_typed: ProstTypedKind,
}

impl BenchmarkConfig {
    pub fn for_message(message_name: &str) -> Self {
        let file_desc_set =
            FileDescriptorSet::decode(BENCH_DESCRIPTOR_SET).expect("decode bench descriptor set");
        let (descriptor_proto, file_proto, package) =
            find_message_and_file(&file_desc_set, message_name);

        let mut registry_descriptor = descriptor_proto.clone();
        registry_descriptor.name = Some(format!("{package}.{message_name}"));
        let registry = MessageRegistry::from_descriptor(&registry_descriptor);

        let mut pool = DescriptorPool::new();
        pool.add_file_descriptor_proto(file_proto.clone())
            .expect("add file descriptor proto");
        let fq_name = format!("{package}.{message_name}");
        let msg_desc = pool
            .get_message_by_name(&fq_name)
            .expect("message descriptor not found in pool");

        let fields = FieldSet::from_descriptor(descriptor_proto);

        Self {
            registry,
            msg_desc,
            fields,
            prost_typed: ProstTypedKind::from_name(message_name),
        }
    }
}

fn find_message_and_file<'a>(
    file_desc_set: &'a FileDescriptorSet,
    message_name: &str,
) -> (
    &'a DescriptorProto,
    &'a prost_types::FileDescriptorProto,
    &'a str,
) {
    for file in &file_desc_set.file {
        for msg_desc in &file.message_type {
            if msg_desc.name.as_deref() == Some(message_name) {
                let package = file.package.as_deref().unwrap_or("");
                return (msg_desc, file, package);
            }
        }
    }
    panic!("message {message_name} not found in descriptor set");
}

fn json_to_proto_bytes(msg_desc: &MessageDescriptor, json: &str) -> Vec<u8> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let msg = DynamicMessage::deserialize(msg_desc.clone(), &mut deserializer)
        .expect("deserialize JSON into proto message");
    deserializer
        .end()
        .expect("unexpected trailing content in JSON input");
    msg.encode_to_vec()
}

pub fn load_bench_sample(key: &str) -> String {
    let value: JsonValue = serde_json::from_str(SAMPLE_DATA_JSON).expect("parse sample data JSON");
    serde_json::to_string(&value[key]).expect("re-serialize sample data section")
}

pub fn bench_prost_reflect_decode(
    msg_desc: &MessageDescriptor,
    encoded_messages: &[Vec<u8>],
) -> u64 {
    let mut total_field_count = 0u64;
    for encoded_bytes in encoded_messages {
        let msg = DynamicMessage::decode(msg_desc.clone(), encoded_bytes.as_slice())
            .expect("decode dynamic message");
        for field in msg_desc.fields() {
            let value = msg.get_field(&field);
            bb(match value.as_ref() {
                Value::I32(v) => *v as u64,
                Value::I64(v) => *v as u64,
                Value::String(v) => v.len() as u64,
                Value::U32(v) => *v as u64,
                Value::U64(v) => *v,
                Value::Bool(v) => *v as u64,
                Value::F32(v) => v.to_bits() as u64,
                Value::F64(v) => v.to_bits(),
                Value::Bytes(v) => v.len() as u64,
                Value::EnumNumber(v) => *v as u64,
                Value::List(v) => v.len() as u64,
                Value::Map(v) => v.len() as u64,
                Value::Message(v) => v.descriptor().name().len() as u64,
            });
            total_field_count += 1;
        }
    }
    total_field_count
}

pub fn bench_prost_typed_decode(kind: ProstTypedKind, encoded_messages: &[Vec<u8>]) -> u64 {
    match kind {
        ProstTypedKind::AirQuality => walk_air_quality(encoded_messages),
        ProstTypedKind::SupportedNullableTypes => walk_supported_nullable_types(encoded_messages),
        ProstTypedKind::WideSchema => walk_wide_schema(encoded_messages),
    }
}

fn walk_air_quality(encoded_messages: &[Vec<u8>]) -> u64 {
    use proto::air_quality::AirQuality;
    let mut total = 0u64;
    for bytes in encoded_messages {
        let m = AirQuality::decode(bytes.as_slice()).expect("decode AirQuality");
        bb(m.device_name.len() as u64);
        bb(m.temp as u64);
        bb(m.humidity as u64);
        total += 3;
    }
    total
}

fn walk_supported_nullable_types(encoded_messages: &[Vec<u8>]) -> u64 {
    use proto::supported_nullable_types::SupportedNullableTypes;
    let mut total = 0u64;
    for bytes in encoded_messages {
        let m = SupportedNullableTypes::decode(bytes.as_slice())
            .expect("decode SupportedNullableTypes");
        bb(m.approved as u64);
        bb(m.day_num as u64);
        bb(m.cost as u64);
        bb(m.discount.to_bits() as u64);
        bb(m.cost_with_discount.to_bits());
        bb(m.description.len() as u64);
        bb(m.photo.len() as u64);
        bb(m.tags.len() as u64);
        bb(m.activity_ratings.len() as u64);
        bb(m.day_activities.len() as u64);
        bb(m.contact_info.len() as u64);
        bb(m.byte_num as u64);
        bb(m.short_num as u64);
        total += 13;
    }
    total
}

fn walk_wide_schema(encoded_messages: &[Vec<u8>]) -> u64 {
    use proto::wide_schema::WideSchema;
    let mut total = 0u64;
    for bytes in encoded_messages {
        let m = WideSchema::decode(bytes.as_slice()).expect("decode WideSchema");
        bb(m.device_id as u64);
        bb(m.device_model.len() as u64);
        bb(m.firmware_version.len() as u64);
        bb(m.hardware_revision.len() as u64);
        bb(m.device_class as u64);
        bb(m.manufacturer_id as u64);
        bb(m.account_id as u64);
        bb(m.org_id as u64);
        bb(m.region_id as u64);
        bb(m.site_id as u64);
        bb(m.site_name.len() as u64);
        bb(m.location_label.len() as u64);
        bb(m.latitude_e6 as u64);
        bb(m.longitude_e6 as u64);
        bb(m.altitude_m as u64);
        bb(m.timezone_offset_min as u64);
        bb(m.boot_time_us as u64);
        bb(m.reading_time_us as u64);
        bb(m.reading_date as u64);
        bb(m.uptime_s as u64);
        bb(m.is_online as u64);
        bb(m.is_charging as u64);
        bb(m.is_battery_powered as u64);
        bb(m.battery_level as u64);
        bb(m.battery_health as u64);
        bb(m.power_mode as u64);
        bb(m.voltage_mv as u64);
        bb(m.current_ma as u64);
        bb(m.temperature_c as u64);
        bb(m.humidity_pct as u64);
        bb(m.pressure_hpa as u64);
        bb(m.co2_ppm as u64);
        bb(m.pm25_ugm3 as u64);
        bb(m.noise_db as u64);
        bb(m.light_lux as u64);
        bb(m.signal_strength as u64);
        bb(m.link_quality as u64);
        bb(m.network_type_id as u64);
        bb(m.network_operator.len() as u64);
        bb(m.apn.len() as u64);
        bb(m.gateway_ip as u64);
        bb(m.peer_ip as u64);
        bb(m.subnet_id as u64);
        bb(m.port as u64);
        bb(m.endpoint_url.len() as u64);
        bb(m.upstream_host.len() as u64);
        bb(m.protocol.len() as u64);
        bb(m.protocol_version as u64);
        bb(m.tls_version_id as u64);
        bb(m.is_encrypted as u64);
        bb(m.send_latency_ms as u64);
        bb(m.dns_latency_ms as u64);
        bb(m.connect_latency_ms as u64);
        bb(m.handshake_latency_ms as u64);
        bb(m.response_latency_ms as u64);
        bb(m.fetch_latency_ms as u64);
        bb(m.retry_count as u64);
        bb(m.error_code as u64);
        bb(m.error_message.len() as u64);
        bb(m.packets_sent as u64);
        bb(m.packets_lost as u64);
        bb(m.bytes_sent as u64);
        bb(m.bytes_received as u64);
        bb(m.session_id.len() as u64);
        bb(m.session_uniq_id as u64);
        bb(m.job_id.len() as u64);
        bb(m.command_label.len() as u64);
        bb(m.command_id as u64);
        bb(m.is_synthetic as u64);
        bb(m.is_healthy as u64);
        bb(m.is_legacy_device as u64);
        bb(m.schema_version as u64);
        bb(m.charset.len() as u64);
        bb(m.locale.len() as u64);
        bb(m.country_code.len() as u64);
        bb(m.status_color.len() as u64);
        bb(m.sensor_id as u64);
        bb(m.sensor_count as u64);
        bb(m.calib_param1 as u64);
        bb(m.calib_param2 as u64);
        bb(m.calib_param3 as u64);
        bb(m.calib_param4 as u64);
        bb(m.config_params.len() as u64);
        bb(m.modem_model.len() as u64);
        bb(m.modem_present as u64);
        bb(m.meter_reading as u64);
        bb(m.unit.len() as u64);
        bb(m.unit_id as u64);
        bb(m.provider_name.len() as u64);
        bb(m.asset_tag.len() as u64);
        bb(m.tag_source.len() as u64);
        bb(m.tag_medium.len() as u64);
        bb(m.tag_group.len() as u64);
        bb(m.has_gps as u64);
        bb(m.gps_fix_quality as u64);
        bb(m.satellites as u64);
        bb(m.cluster_id as u64);
        bb(m.shard_id as u64);
        bb(m.upstream_hash as u64);
        bb(m.record_hash as u64);
        total += 100;
    }
    total
}

pub fn bench_zeroparser_decode(
    registry: &MessageRegistry,
    fields: &FieldSet,
    encoded_messages: &[Vec<u8>],
) -> u64 {
    let mut total_field_count = 0u64;
    for encoded_bytes in encoded_messages {
        let collected = ParsedMessage::parse(encoded_bytes, registry).expect("parse message");
        for &field_num in &fields.scalars {
            total_field_count += 1;
            match collected.get_scalar(field_num) {
                Some(scalar) => bb(match *scalar {
                    FieldValueRef::String(s) => s.len() as u64,
                    FieldValueRef::Int32(v) => v as u64,
                    FieldValueRef::Int64(v) => v as u64,
                    FieldValueRef::UInt32(v) => v as u64,
                    FieldValueRef::UInt64(v) => v,
                    FieldValueRef::Bool(v) => v as u64,
                    FieldValueRef::Float(v) => v.to_bits() as u64,
                    FieldValueRef::Double(v) => v.to_bits(),
                    FieldValueRef::Bytes(b) => b.len() as u64,
                }),
                None => bb(0u64),
            };
        }
        for &field_num in &fields.repeated_scalars {
            bb(collected.get_repeated_scalars(field_num).len() as u64);
            total_field_count += 1;
        }
        for &field_num in &fields.repeated_messages {
            bb(collected.get_repeated_messages(field_num).len() as u64);
            total_field_count += 1;
        }
        for &field_num in &fields.maps {
            bb(collected.get_map_entries_count(field_num) as u64);
            total_field_count += 1;
        }
    }
    total_field_count
}

pub fn create_sized_message(
    msg_desc: &MessageDescriptor,
    base_json: &str,
    padding_field: &str,
    target_size: usize,
) -> Vec<u8> {
    let base_encoded = json_to_proto_bytes(msg_desc, base_json);
    let base_size = base_encoded.len();
    if target_size <= base_size {
        return base_encoded;
    }

    let padding_needed = target_size - base_size;
    let mut json_value: JsonValue = serde_json::from_str(base_json).expect("parse base JSON");
    if let Some(field) = json_value.get_mut(padding_field) {
        let current_value = field.as_str().unwrap_or("");
        let padding: String = "x".repeat(padding_needed);
        *field = JsonValue::String(format!("{current_value}{padding}"));
    }
    let padded_json = serde_json::to_string(&json_value).expect("re-serialize padded JSON");
    json_to_proto_bytes(msg_desc, &padded_json)
}

#[allow(dead_code)]
pub fn create_encoded_messages(
    msg_desc: &MessageDescriptor,
    base_json: &str,
    padding_field: &str,
    target_size: usize,
    count: usize,
) -> Vec<Vec<u8>> {
    let message = create_sized_message(msg_desc, base_json, padding_field, target_size);
    vec![message; count]
}

pub fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}
