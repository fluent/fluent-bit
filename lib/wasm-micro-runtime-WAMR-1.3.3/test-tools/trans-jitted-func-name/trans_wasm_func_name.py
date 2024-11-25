#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
"""
It is used to translate jitted functions' names(in out.folded) to coorespond name in name section in .wasm

Usage:

After
```
$ perf script -i perf.data > out.perf

# fold call stacks
$ ./FlameGraph/stackcollapse-perf.pl out.perf > out.folded
```

Add a step:
```
# translate jitted functions' names
$ python translate_wasm_function_name.py --wabt_home <wabt-installation> --folded out.folded <.wasm>
# out.folded -> out.folded.translated
$ ls out.folded.translated
```

Then
```
# generate flamegraph
$ ./FlameGraph/flamegraph.pl out.folded.translated > perf.wasm.svg
```

"""

import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess


def preflight_check(wabt_home: Path) -> Path:
    """
    if wasm-objdump exists in wabt_home
    """
    wasm_objdump_bin = wabt_home.joinpath("bin", "wasm-objdump")
    if not wasm_objdump_bin.exists():
        raise RuntimeError(f"wasm-objdump not found in {wabt_home}")

    return wasm_objdump_bin


def collect_import_section_content(wasm_objdump_bin: Path, wasm_file: Path) -> dict:
    """
    execute "wasm_objdump_bin -j Import -x <wasm_file>" and return a dict like {function: X, global: Y, memory: Z, table: N}
    """
    assert wasm_objdump_bin.exists()
    assert wasm_file.exists()

    command = f"{wasm_objdump_bin} -j Import -x {wasm_file}"
    p = subprocess.run(
        shlex.split(command),
        capture_output=True,
        check=False,
        text=True,
        universal_newlines=True,
    )

    if p.stderr:
        return {}

    import_section = {}
    for line in p.stdout.split(os.linesep):
        line = line.strip()

        if not line:
            continue

        if line.startswith(" - func"):
            import_section.update("function", import_section.get("function", 0) + 1)
        else:
            pass

    return import_section


def collect_name_section_content(wasm_objdump_bin: Path, wasm_file: Path) -> dict:
    """
    execute "wasm_objdump_bin -j name -x wasm_file" and store the output in a list
    """
    assert wasm_objdump_bin.exists()
    assert wasm_file.exists()

    command = f"{wasm_objdump_bin} -j name -x {wasm_file}"
    p = subprocess.run(
        shlex.split(command),
        capture_output=True,
        check=False,
        text=True,
        universal_newlines=True,
    )

    if p.stderr:
        raise RuntimeError(f"not found name section in {wasm_file}")

    name_section = {}
    for line in p.stdout.split(os.linesep):
        line = line.strip()

        if not line:
            continue

        # - func[0] <__imported_wasi_snapshot_preview1_fd_close>
        if line.startswith("- func"):
            m = re.match(r"- func\[(\d+)\] <(.+)>", line)
            assert m

            func_index, func_name = m.groups()
            name_section.update({func_index: func_name})

    assert name_section
    return name_section


def replace_function_name(
    import_section: dict, name_section: dict, folded_in: str, folded_out: str
) -> None:
    """
    read content in <folded_in>. each line will be like:

    quiche::BalsaFrame::ProcessHeaders;non-virtual thunk to Envoy::Http::Http1::BalsaParser::MessageDone;Envoy::Http::Http1::ConnectionImpl::onMessageComplete;Envoy::Http::Http1::ConnectionImpl::onMessageCompleteImpl;Envoy::Http::Http1::ServerConnectionImpl::onMessageCompleteBase;Envoy::Http::ConnectionManagerImpl::ActiveStream::decodeHeaders;Envoy::Http::FilterManager::decodeHeaders;virtual thunk to Envoy::Extensions::Common::Wasm::Context::decodeHeaders;proxy_wasm::ContextBase::onRequestHeaders;proxy_wasm::wamr::Wamr::getModuleFunctionImpl<proxy_wasm::Word, proxy_wasm::Word, proxy_wasm::Word, proxy_wasm::Word>;wasm_func_call;wasm_runtime_call_wasm;wasm_call_function;call_wasm_with_hw_bound_check;wasm_interp_call_wasm;llvm_jit_call_func_bytecode;wasm_runtime_invoke_native;push_args_end;aot_func_internal#3302;aot_func_internal#3308;asm_sysvec_apic_timer_interrupt;sysvec_apic_timer_interrupt;__sysvec_apic_timer_interrupt;hrtimer_interrupt;__hrtimer_run_queues;__remove_hrtimer;rb_next 1110899

    symbol names are spearated by ";"

    if there is a symbol named like "aot_func#XXX" or "aot_func_internal#XXX", it will be replaced with the function name in name section by index
    """
    folded_in = Path(folded_in)
    assert folded_in.exists()
    folded_out = Path(folded_out)

    import_function_count = import_section.get("function", 0)
    with folded_in.open("rt", encoding="utf-8") as f_in, folded_out.open(
        "wt", encoding="utf-8"
    ) as f_out:
        precheck_mode = False
        for line in f_in:
            line = line.strip()
            if "aot_func_internal" in line:
                precheck_mode = True

        f_in.seek(0)
        for line in f_in:
            new_line = []
            line = line.strip()

            m = re.match(r"(.*) (\d+)", line)
            syms, samples = m.groups()
            for sym in syms.split(";"):
                m = re.match(r"aot_func(_internal)?#(\d+)", sym)
                if not m:
                    new_line.append(sym)
                    continue

                func_idx = m.groups()[-1]
                if func_idx in name_section:
                    wasm_func_name = f"[Wasm] {name_section[func_idx]}"
                else:
                    wasm_func_name = (
                        f"[Wasm] function[{func_idx + import_function_count}]"
                    )

                if precheck_mode:
                    # aot_func_internal -> xxx
                    # aot_func --> xxx_precheck
                    wasm_func_name += "_precheck" if not m.groups()[0] else ""
                else:
                    # aot_func --> xxx
                    pass

                new_line.append(wasm_func_name)

            line = ";".join(new_line)
            line += f" {samples}"
            f_out.write(line + os.linesep)

    print(f"⚙️ {folded_in} -> {folded_out}")


def main(wabt_home: str, wasm_file: str, folded: str) -> None:
    wabt_home = Path(wabt_home)
    wasm_file = Path(wasm_file)

    wasm_objdump_bin = preflight_check(wabt_home)
    import_section = collect_import_section_content(wasm_objdump_bin, wasm_file)
    name_section = collect_name_section_content(wasm_objdump_bin, wasm_file)

    replace_function_name(import_section, name_section, folded, folded + ".translated")


if __name__ == "__main__":
    argparse = argparse.ArgumentParser()
    argparse.add_argument(
        "--folded", help="stackcollapse-perf.pl generated, like out.folded"
    )
    argparse.add_argument("wasm_file", help="wasm file")
    argparse.add_argument("--wabt_home", help="wabt home, like /opt/wabt-1.0.33")

    args = argparse.parse_args()
    main(args.wabt_home, args.wasm_file, args.folded)
