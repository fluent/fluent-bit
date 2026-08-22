mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::{
    bench_prost_reflect_decode, bench_prost_typed_decode, bench_zeroparser_decode,
    create_sized_message, format_bytes, load_bench_sample, BenchmarkConfig,
};
use plotters::prelude::*;
use plotters::style::text_anchor::{HPos, Pos, VPos};

const OUTPUT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/zeroparser/benches/bench_plot.svg"
);
const MIN_MEASURE_SECS: f64 = 1.0;
const MAX_ITERATIONS: u64 = 1_000;
const TRIALS_PER_MEASUREMENT: usize = 3;

// C++ libprotobuf MB/s, measured out-of-tree on the bytes this binary dumps
// via ZEROPARSER_CPP_DUMP_DIR=... See e2e/benches/README.md to re-measure.
struct CppBaseline {
    reflect_mbps: f64,
    typed_mbps: f64,
}

fn cpp_baselines() -> HashMap<&'static str, CppBaseline> {
    let mut m = HashMap::new();
    m.insert(
        "AirQuality@32B",
        CppBaseline {
            reflect_mbps: 593.0,
            typed_mbps: 955.0,
        },
    );
    m.insert(
        "AirQuality@201B",
        CppBaseline {
            reflect_mbps: 3300.0,
            typed_mbps: 4988.0,
        },
    );
    m.insert(
        "AirQuality@1025B",
        CppBaseline {
            reflect_mbps: 9519.0,
            typed_mbps: 11682.0,
        },
    );
    m.insert(
        "SupportedNullableTypes@1025B",
        CppBaseline {
            reflect_mbps: 1813.0,
            typed_mbps: 2048.0,
        },
    );
    // WideSchema (100-field device-telemetry record), libprotobuf 32.1, mean of
    // 3 runs of the out-of-tree harness (see benches/README.md).
    m.insert(
        "WideSchema@1025B",
        CppBaseline {
            reflect_mbps: 608.0,
            typed_mbps: 1042.0,
        },
    );
    m
}

struct PlotScenario {
    label: &'static str,
    config: BenchmarkConfig,
    sample_json: String,
    padding_field: &'static str,
    target_size: usize,
    count: usize,
}

impl PlotScenario {
    fn dump_key(&self, record_bytes: usize) -> String {
        format!("{}@{}B", self.label, record_bytes)
    }
}

fn air_quality_scenarios() -> Vec<PlotScenario> {
    [32usize, 200, 1024]
        .into_iter()
        .map(|size| PlotScenario {
            label: "AirQuality",
            config: BenchmarkConfig::for_message("AirQuality"),
            sample_json: r#"{"device_name":"sensor_01","temp":25,"humidity":65}"#.to_string(),
            padding_field: "device_name",
            target_size: size,
            count: 50_000,
        })
        .collect()
}

fn supported_nullable_types_scenario() -> PlotScenario {
    PlotScenario {
        label: "SupportedNullableTypes",
        config: BenchmarkConfig::for_message("SupportedNullableTypes"),
        sample_json: load_bench_sample("supported_nullable_types_json"),
        padding_field: "description",
        target_size: 1_024,
        count: 50_000,
    }
}

fn wide_schema_scenario() -> PlotScenario {
    PlotScenario {
        label: "WideSchema",
        config: BenchmarkConfig::for_message("WideSchema"),
        sample_json: load_bench_sample("wide_schema_json"),
        padding_field: "endpoint_url",
        target_size: 1_024,
        count: 50_000,
    }
}

struct Measurement {
    label: &'static str,
    record_bytes: usize,
    reflect_mbps: f64,
    prost_typed_mbps: f64,
    cpp_reflect_mbps: f64,
    cpp_typed_mbps: f64,
    zeroparser_mbps: f64,
}

fn measure_mbps<F>(encoded_messages: &[Vec<u8>], mut decode: F) -> f64
where
    F: FnMut(&[Vec<u8>]) -> u64,
{
    let total_bytes: usize = encoded_messages.iter().map(|m| m.len()).sum();
    let target = Duration::from_secs_f64(MIN_MEASURE_SECS);

    let mut sum_mbps = 0.0f64;
    for _ in 0..TRIALS_PER_MEASUREMENT {
        let warmup_start = Instant::now();
        decode(encoded_messages);
        let warm_batch = warmup_start.elapsed();

        let iters = if warm_batch.is_zero() {
            MAX_ITERATIONS
        } else {
            ((target.as_nanos() / warm_batch.as_nanos().max(1)) as u64).clamp(1, MAX_ITERATIONS)
        };

        let start = Instant::now();
        for _ in 0..iters {
            decode(encoded_messages);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let bytes_processed = (total_bytes * iters as usize) as f64;
        sum_mbps += bytes_processed / (1024.0 * 1024.0) / elapsed;
    }
    sum_mbps / TRIALS_PER_MEASUREMENT as f64
}

fn measure_scenario(
    scenario: &PlotScenario,
    dump_dir: Option<&PathBuf>,
    cpp: &HashMap<&'static str, CppBaseline>,
) -> Measurement {
    let single = create_sized_message(
        &scenario.config.msg_desc,
        &scenario.sample_json,
        scenario.padding_field,
        scenario.target_size,
    );
    let record_bytes = single.len();

    if let Some(dir) = dump_dir {
        let path = dir.join(format!("{}.bin", scenario.dump_key(record_bytes)));
        std::fs::write(&path, &single)
            .unwrap_or_else(|e| panic!("dump {} to {}: {e}", scenario.label, path.display()));
    }

    let messages = vec![single; scenario.count];

    let reflect_mbps = measure_mbps(&messages, |m| {
        bench_prost_reflect_decode(&scenario.config.msg_desc, m)
    });

    let prost_typed_mbps = measure_mbps(&messages, |m| {
        bench_prost_typed_decode(scenario.config.prost_typed, m)
    });

    let zeroparser_mbps = measure_mbps(&messages, |m| {
        bench_zeroparser_decode(&scenario.config.registry, &scenario.config.fields, m)
    });

    let key = scenario.dump_key(record_bytes);
    let baseline = cpp.get(key.as_str());
    let cpp_reflect_mbps = baseline.map(|b| b.reflect_mbps).unwrap_or(0.0);
    let cpp_typed_mbps = baseline.map(|b| b.typed_mbps).unwrap_or(0.0);

    Measurement {
        label: scenario.label,
        record_bytes,
        reflect_mbps,
        prost_typed_mbps,
        cpp_reflect_mbps,
        cpp_typed_mbps,
        zeroparser_mbps,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dump_dir = std::env::var_os("ZEROPARSER_CPP_DUMP_DIR").map(PathBuf::from);
    if let Some(dir) = dump_dir.as_ref() {
        std::fs::create_dir_all(dir)?;
        println!("dumping encoded sample messages to {}", dir.display());
    }

    let cpp = cpp_baselines();

    let mut scenarios = air_quality_scenarios();
    scenarios.push(supported_nullable_types_scenario());
    scenarios.push(wide_schema_scenario());

    let results: Vec<Measurement> = scenarios
        .iter()
        .map(|s| {
            let m = measure_scenario(s, dump_dir.as_ref(), &cpp);
            println!(
                "{:<22} ({:>7})  prost_reflect={:>7.1}  prost={:>7.1}  cpp_reflect={:>7.1}  cpp_typed={:>7.1}  zeroparser={:>7.1} MB/s",
                m.label,
                format_bytes(m.record_bytes),
                m.reflect_mbps,
                m.prost_typed_mbps,
                m.cpp_reflect_mbps,
                m.cpp_typed_mbps,
                m.zeroparser_mbps,
            );
            m
        })
        .collect();

    if let Some(dir) = dump_dir.as_ref() {
        let manifest = dir.join("scenarios.txt");
        let lines: String = results
            .iter()
            .map(|m| format!("{},{}\n", m.label, m.record_bytes))
            .collect();
        std::fs::write(&manifest, lines)?;
        println!("wrote manifest {}", manifest.display());
    }

    draw_plot(&results)?;
    println!("Wrote {OUTPUT_PATH}");
    Ok(())
}

type Bar = (&'static str, RGBColor, fn(&Measurement) -> f64);

fn draw_plot(results: &[Measurement]) -> Result<(), Box<dyn std::error::Error>> {
    let root = SVGBackend::new(OUTPUT_PATH, (1280, 560)).into_drawing_area();
    root.fill(&WHITE)?;

    let bars_per_group: &[Bar] = &[
        ("prost-reflect", RGBColor(220, 80, 80), |m| m.reflect_mbps),
        ("prost", RGBColor(235, 145, 70), |m| m.prost_typed_mbps),
        ("C++ reflect", RGBColor(120, 100, 180), |m| {
            m.cpp_reflect_mbps
        }),
        ("C++ typed", RGBColor(95, 165, 110), |m| m.cpp_typed_mbps),
        ("Zeroparser", RGBColor(60, 130, 200), |m| m.zeroparser_mbps),
    ];

    let max_mbps = results
        .iter()
        .flat_map(|m| bars_per_group.iter().map(move |(_, _, f)| f(m)))
        .fold(0f64, f64::max);
    let y_max = (max_mbps * 1.18).max(10.0);

    let group_count = results.len();
    let bar_count = bars_per_group.len() as f64;
    let group_span = 0.86f64;
    let bar_width = group_span / bar_count;

    let mut chart = ChartBuilder::on(&root)
        .caption(
            "Decode throughput: prost-reflect vs prost vs C++ protobuf vs Zeroparser",
            ("sans-serif", 24).into_font(),
        )
        .margin(20)
        .x_label_area_size(60)
        .y_label_area_size(80)
        .build_cartesian_2d(-0.5f64..(group_count as f64 - 0.5), 0.0f64..y_max)?;

    chart
        .configure_mesh()
        .disable_x_mesh()
        .y_desc("MB/s")
        .x_labels(group_count)
        .x_label_formatter(&|x| {
            let idx = x.round() as i64;
            if idx >= 0 && (idx as usize) < results.len() {
                let m = &results[idx as usize];
                format!("{} ({})", m.label, format_bytes(m.record_bytes))
            } else {
                String::new()
            }
        })
        .axis_desc_style(("sans-serif", 18))
        .label_style(("sans-serif", 16))
        .draw()?;

    let number_style = ("sans-serif", 12)
        .into_font()
        .color(&BLACK)
        .pos(Pos::new(HPos::Center, VPos::Bottom));

    for (i, m) in results.iter().enumerate() {
        let group_left = i as f64 - group_span / 2.0;
        for (slot, (_, color, getter)) in bars_per_group.iter().enumerate() {
            let value = getter(m);
            let x0 = group_left + slot as f64 * bar_width;
            let x1 = x0 + bar_width * 0.94;

            chart.draw_series(std::iter::once(Rectangle::new(
                [(x0, 0.0), (x1, value)],
                color.filled(),
            )))?;

            let label_pad = y_max * 0.012;
            let text = if value > 0.0 {
                format!("{value:.0}")
            } else {
                "n/a".to_string()
            };
            chart.draw_series(std::iter::once(Text::new(
                text,
                ((x0 + x1) / 2.0, value.max(0.0) + label_pad),
                number_style.clone(),
            )))?;
        }
    }

    for (name, color, _) in bars_per_group {
        let c = *color;
        chart
            .draw_series(std::iter::once(Rectangle::new(
                [(0.0, 0.0), (0.0, 0.0)],
                c.filled(),
            )))?
            .label(*name)
            .legend(move |(x, y)| Rectangle::new([(x, y - 6), (x + 18, y + 6)], c.filled()));
    }

    chart
        .configure_series_labels()
        .border_style(BLACK)
        .background_style(WHITE.mix(0.9))
        .label_font(("sans-serif", 15))
        .position(SeriesLabelPosition::UpperRight)
        .draw()?;

    root.present()?;
    Ok(())
}
