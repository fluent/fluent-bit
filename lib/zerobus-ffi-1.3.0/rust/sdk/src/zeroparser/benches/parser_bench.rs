mod common;

use common::{
    bench_prost_reflect_decode, bench_prost_typed_decode, bench_zeroparser_decode,
    create_encoded_messages, format_bytes, load_bench_sample, BenchmarkConfig,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

struct BenchScenario {
    group_name: &'static str,
    config: BenchmarkConfig,
    sample_json: String,
    padding_field: &'static str,
    message_sizes: &'static [usize],
    message_counts: &'static [usize],
}

fn air_quality_scenario() -> BenchScenario {
    BenchScenario {
        group_name: "air_quality_decode",
        config: BenchmarkConfig::for_message("AirQuality"),
        sample_json: r#"{"device_name":"sensor_01","temp":25,"humidity":65}"#.to_string(),
        padding_field: "device_name",
        message_sizes: &[32, 256, 1_024],
        message_counts: &[10_000, 100_000],
    }
}

fn wide_schema_scenario() -> BenchScenario {
    BenchScenario {
        group_name: "wide_schema_decode",
        config: BenchmarkConfig::for_message("WideSchema"),
        sample_json: load_bench_sample("wide_schema_json"),
        padding_field: "endpoint_url",
        message_sizes: &[1_024],
        message_counts: &[100_000, 1_000_000],
    }
}

fn supported_nullable_types_scenario() -> BenchScenario {
    BenchScenario {
        group_name: "supported_nullable_types_decode",
        config: BenchmarkConfig::for_message("SupportedNullableTypes"),
        sample_json: load_bench_sample("supported_nullable_types_json"),
        padding_field: "description",
        message_sizes: &[128, 512, 1_024],
        message_counts: &[10_000, 100_000],
    }
}

fn run_decode_benchmark(c: &mut Criterion, scenario: BenchScenario) {
    let mut group = c.benchmark_group(scenario.group_name);

    for &target_size in scenario.message_sizes {
        for &count in scenario.message_counts {
            let encoded_messages = create_encoded_messages(
                &scenario.config.msg_desc,
                &scenario.sample_json,
                scenario.padding_field,
                target_size,
                count,
            );
            let actual_message_size = encoded_messages.first().map(|m| m.len()).unwrap_or(0);
            let total_bytes = actual_message_size * count;
            let description = format_args!(
                "{} size x {} messages",
                format_bytes(actual_message_size),
                count
            );
            group.throughput(Throughput::Bytes(total_bytes as u64));

            group.bench_with_input(
                BenchmarkId::new("prost_reflect", description),
                &encoded_messages,
                |b, messages| {
                    b.iter(|| bench_prost_reflect_decode(&scenario.config.msg_desc, messages));
                },
            );

            group.bench_with_input(
                BenchmarkId::new("prost", description),
                &encoded_messages,
                |b, messages| {
                    b.iter(|| bench_prost_typed_decode(scenario.config.prost_typed, messages));
                },
            );

            group.bench_with_input(
                BenchmarkId::new("zeroparser", description),
                &encoded_messages,
                |b, messages| {
                    b.iter(|| {
                        bench_zeroparser_decode(
                            &scenario.config.registry,
                            &scenario.config.fields,
                            messages,
                        )
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_air_quality(c: &mut Criterion) {
    run_decode_benchmark(c, air_quality_scenario());
}

fn bench_wide_schema(c: &mut Criterion) {
    run_decode_benchmark(c, wide_schema_scenario());
}

fn bench_supported_nullable_types(c: &mut Criterion) {
    run_decode_benchmark(c, supported_nullable_types_scenario());
}

criterion_group! {
    name = parser_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_air_quality, bench_wide_schema, bench_supported_nullable_types,
}

criterion_main!(parser_benches);
