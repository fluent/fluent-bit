#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

from dataclasses import dataclass
from pathlib import Path
from pprint import pprint
import re
import shlex
import shutil
import subprocess
from typing import List


@dataclass
class WasmEdgeExampleResult:
    class_id: int
    possibility: float


def execute_once(
    runtime_bin: str,
    runtime_args: List[str],
    wasm_file: str,
    wasm_args: List[str],
    cwd: Path,
) -> str:
    cmd = [runtime_bin]
    cmd.extend(runtime_args)
    cmd.append(wasm_file)
    cmd.extend(wasm_args)

    # print(f'Execute: {" ".join(cmd)}')

    p = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        check=True,
        text=True,
        universal_newlines=True,
    )
    return p.stdout


def execute_openvino_road_segmentation_adas_once(
    runtime_bin: str, runtime_args: List[str], cwd: Path
) -> str:
    """
    execute openvino-road-segmentation-adas with iwasm and wasmedge
    """

    wasm_file = (
        "./openvino-road-seg-adas/target/wasm32-wasip1/debug/openvino-road-seg-adas.wasm"
    )
    wasm_args = [
        "./model/road-segmentation-adas-0001.xml",
        "./model/road-segmentation-adas-0001.bin",
        "./image/empty_road_mapillary.jpg",
    ]
    return execute_once(runtime_bin, runtime_args, wasm_file, wasm_args, cwd)


def execute_openvino_mobilenet_raw_once(
    runtime_bin: str, runtime_args: List[str], cwd: Path
) -> str:
    """
    execute openvino-mobilenet-image with iwasm and wasmedge
    """

    wasm_file = "./rust/target/wasm32-wasip1/debug/wasmedge-wasinn-example-mobilenet.wasm"
    wasm_args = [
        "mobilenet.xml",
        "mobilenet.bin",
        "./tensor-1x224x224x3-f32.bgr",
    ]
    return execute_once(runtime_bin, runtime_args, wasm_file, wasm_args, cwd)


def execute_openvino_mobilenet_image_once(
    runtime_bin: str, runtime_args: List[str], cwd: Path
) -> str:
    """
    execute openvino-mobilenet-image with iwasm and wasmedge
    """

    wasm_file = (
        "./rust/target/wasm32-wasip1/debug/wasmedge-wasinn-example-mobilenet-image.wasm"
    )
    wasm_args = [
        "mobilenet.xml",
        "mobilenet.bin",
        "input.jpg",
    ]
    return execute_once(runtime_bin, runtime_args, wasm_file, wasm_args, cwd)


def execute_tflite_birds_v1_image_once(
    runtime_bin: str, runtime_args: List[str], cwd: Path
) -> str:
    """
    execute openvino-mobilenet-image with iwasm and wasmedge
    """

    wasm_file = (
        "rust/target/wasm32-wasip1/debug/wasmedge-wasinn-example-tflite-bird-image.wasm"
    )
    wasm_args = ["lite-model_aiy_vision_classifier_birds_V1_3.tflite", "bird.jpg"]
    return execute_once(runtime_bin, runtime_args, wasm_file, wasm_args, cwd)


def filter_output(output: str) -> List[WasmEdgeExampleResult]:
    """
    not all output is required for comparison

    pick lines like: " 1.) [166](198)Aix galericulata"
    """
    filtered = []
    PATTERN = re.compile(r"^\s+\d\.\)\s+\[(\d+)\]\(([.0-9]+)\)\w+")
    for line in output.split("\n"):
        m = PATTERN.search(line)
        if m:
            class_id, possibility = m.groups()
            filtered.append(WasmEdgeExampleResult(class_id, possibility))

    assert len(filtered)
    return filtered


def compare_output(
    iwasm_output: List[WasmEdgeExampleResult],
    wasmedge_output: List[WasmEdgeExampleResult],
) -> bool:
    """
    only compare top 2 and ignore possibility
    """
    return (iwasm_output[0].class_id, iwasm_output[1].class_id) == (
        wasmedge_output[0].class_id,
        wasmedge_output[1].class_id,
    )


def summarizer_result(
    example_name: str,
    iwasm_output: List[WasmEdgeExampleResult],
    wasmedge_output: List[WasmEdgeExampleResult],
):
    if compare_output(iwasm_output, wasmedge_output):
        print(f"- {example_name}. PASS")
        return

    print(f"- {example_name}. FAILED")
    print("------------------------------------------------------------")
    pprint(iwasm_output)
    print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
    pprint(wasmedge_output)
    print("------------------------------------------------------------")


def execute_tflite_birds_v1_image(iwasm_bin: str, wasmedge_bin: str, cwd: Path):
    iwasm_output = execute_tflite_birds_v1_image_once(
        iwasm_bin,
        [
            "--map-dir=.::.",
        ],
        cwd,
    )
    iwasm_output = filter_output(iwasm_output)

    wasmedge_output = execute_tflite_birds_v1_image_once(
        wasmedge_bin, ["--dir=.:."], cwd
    )
    wasmedge_output = filter_output(wasmedge_output)

    summarizer_result("tf_lite_birds_v1_image", iwasm_output, wasmedge_output)


def execute_openvino_mobilenet_image(iwasm_bin: str, wasmedge_bin: str, cwd: Path):
    iwasm_output = execute_openvino_mobilenet_image_once(
        iwasm_bin,
        [
            "--map-dir=.::.",
        ],
        cwd,
    )
    iwasm_output = filter_output(iwasm_output)

    wasmedge_output = execute_openvino_mobilenet_image_once(
        wasmedge_bin, ["--dir=.:."], cwd
    )
    wasmedge_output = filter_output(wasmedge_output)

    summarizer_result("openvino_mobile_image", iwasm_output, wasmedge_output)


def execute_openvino_mobilenet_raw(iwasm_bin: str, wasmedge_bin: str, cwd: Path):
    iwasm_output = execute_openvino_mobilenet_raw_once(
        iwasm_bin,
        [
            "--map-dir=.::.",
        ],
        cwd,
    )
    iwasm_output = filter_output(iwasm_output)

    wasmedge_output = execute_openvino_mobilenet_raw_once(
        wasmedge_bin, ["--dir=.:."], cwd
    )
    wasmedge_output = filter_output(wasmedge_output)

    summarizer_result("openvino_mobile_raw", iwasm_output, wasmedge_output)


def execute_openvino_road_segmentation_adas(
    iwasm_bin: str, wasmedge_bin: str, cwd: Path
):
    def filter_output(output: str) -> str:
        """
        focus on lines:
           The size of the output buffer is 7340032 bytes
           dump tensor to "wasinn-openvino-inference-output-1x4x512x896xf32.tensor"
        """
        for line in output.split("\n"):
            if "The size of the output buffer is" in line:
                dump_tensor_size = int(line.split(" ")[-2])
                continue

            if "dump tensor to " in line:
                dump_tensor_file = line.split(" ")[-1]
                continue

        return (dump_tensor_file, dump_tensor_size)

    iwasm_output = execute_openvino_road_segmentation_adas_once(
        iwasm_bin,
        [
            "--map-dir=.::.",
        ],
        cwd,
    )
    iwasm_tensor_file, iwasm_tensor_size = filter_output(iwasm_output)

    wasmedge_output = execute_openvino_road_segmentation_adas_once(
        wasmedge_bin, ["--dir=.:."], cwd
    )
    wasmedge_tensor_file, wasmedge_tensor_size = filter_output(wasmedge_output)

    # TODO: binary compare?
    if iwasm_tensor_size == wasmedge_tensor_size:
        print(f"- openvino_road_segmentation_adas. PASS")
        return

    print(f"- openvino_road_segmentation_adas. FAILED")
    print("------------------------------------------------------------")
    print(f"FILE:{iwasm_tensor_file}, SIZE:{iwasm_tensor_size}")
    print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
    print(f"FILE:{wasmedge_tensor_file}, SIZE:{wasmedge_tensor_size}")
    print("------------------------------------------------------------")


def execute_wasmedge_ggml_qwen(iwasm_bin: str, wasmedge_bin: str, cwd: Path):
    iwasm_args = ["--dir=."]
    wasm_file = ["./target/wasm32-wasip1/debug/wasmedge-ggml-qwen.wasm"]
    wasm_args = ["./qwen1_5-0_5b-chat-q2_k.gguf"]

    cmd = [iwasm_bin]
    cmd.extend(iwasm_args)
    cmd.extend(wasm_file)
    cmd.extend(wasm_args)

    # print(f'Execute: {" ".join(cmd)}')

    prompt = "what is the capital of Pakistan"

    with subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
    ) as p:
        # USER
        p.stdout.readline()

        p.stdin.write(b"hi\n")
        p.stdin.flush()
        # ASSISTANT
        p.stdout.readline()
        # xxx
        p.stdout.readline()
        # USER
        p.stdout.readline()

        p.stdin.write(prompt.encode())
        p.stdin.write(b"\n")
        p.stdin.flush()
        # ASSISTANT
        p.stdout.readline()
        # xxx
        answer = p.stdout.readline().decode("utf-8")
        # USER
        p.stdout.readline()

        p.terminate()

    if "Karachi" in answer:
        print(f"- wasmedge_ggml_qwen. PASS")
        return

    print(f"- wasmedge_ggml_qwen. FAILED")
    print("------------------------------------------------------------")
    pprint(answer)
    print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
    pprint("Karachi")
    print("------------------------------------------------------------")


def execute_wasmedge_wasinn_examples(iwasm_bin: str, wasmedge_bin: str):
    assert Path.cwd().name == "wasmedge-wasinn-examples"
    assert shutil.which(iwasm_bin)
    assert shutil.which(wasmedge_bin)

    # TODO: keep commenting until https://github.com/bytecodealliance/wasm-micro-runtime/pull/3597 is merged
    # tflite_birds_v1_image_dir = Path.cwd().joinpath("./tflite-birds_v1-image")
    # execute_tflite_birds_v1_image(iwasm_bin, wasmedge_bin, tflite_birds_v1_image_dir)

    openvino_mobile_image_dir = Path.cwd().joinpath("./openvino-mobilenet-image")
    execute_openvino_mobilenet_image(iwasm_bin, wasmedge_bin, openvino_mobile_image_dir)

    openvino_mobile_raw_dir = Path.cwd().joinpath("./openvino-mobilenet-raw")
    execute_openvino_mobilenet_raw(iwasm_bin, wasmedge_bin, openvino_mobile_raw_dir)

    openvino_road_segmentation_adas_dir = Path.cwd().joinpath(
        "./openvino-road-segmentation-adas"
    )
    execute_openvino_road_segmentation_adas(
        iwasm_bin, wasmedge_bin, openvino_road_segmentation_adas_dir
    )

    wasmedge_ggml_qwem_dir = Path.cwd().joinpath("./wasmedge-ggml/qwen")
    execute_wasmedge_ggml_qwen(iwasm_bin, wasmedge_bin, wasmedge_ggml_qwem_dir)


if __name__ == "__main__":
    execute_wasmedge_wasinn_examples("iwasm", "wasmedge")
