"""Bounded, opt-in Docker reproduction; no Azure account or host trust changes."""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid


HERE = Path(__file__).resolve().parent
PUBLIC_IMAGE = (
    "mcr.microsoft.com/oss/v2/fluent/fluent-bit@"
    "sha256:8ae255ac04173aff52e73bac6072fb8100870d05c1a97432e20befeab0c6067f"
)


def docker(*args, timeout=120):
    result = subprocess.run(
        ["docker", *map(str, args)], capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed ({result.returncode}): {result.stderr}")
    return result.stdout.strip()


def configuration(outputs, workers, hostname, buffering):
    text = """[SERVICE]
    Flush 1
    Grace 2
    Log_Level debug
[INPUT]
    Name dummy
    Tag local
    Rate 1
    Dummy {"message":"offline-test-only"}
"""
    for index in range(outputs):
        text += f"""[OUTPUT]
    Name azure_kusto
    Match local
    tenant_id LOCAL_DUMMY_TENANT
    client_id LOCAL_DUMMY_CLIENT
    client_secret LOCAL_DUMMY_PLACEHOLDER
    auth_type service_principal
    ingestion_endpoint https://mock.local
    database_name offline
    table_name table{index}
    buffering_enabled {"on" if buffering else "off"}
    buffer_dir /tmp/kusto{index}
    compression_enabled on
    ingestion_resources_refresh_interval 1s
    workers {workers}
    retry_limit 5
    tls.verify on
    tls.verify_hostname {"on" if hostname else "off"}
"""
    return text


def container_logs(name):
    result = subprocess.run(
        ["docker", "logs", name], capture_output=True, text=True, timeout=30
    )
    result.check_returncode()
    return result.stdout + result.stderr


def rotation_counts(logs, message):
    counts = collections.Counter()
    for line in logs.splitlines():
        if message in line:
            match = re.search(r"\[output:azure_kusto:([^\]]+)\]", line)
            counts[match.group(1) if match else "unknown"] += 1
    return dict(counts)


def run_case(args):
    prefix = "kusto-probe-" + uuid.uuid4().hex[:12]
    network = prefix + "-net"
    created = []
    network_created = False
    output = Path(args.result).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError(f"Refusing to overwrite result: {output}")
    summary = {}
    with tempfile.TemporaryDirectory(prefix=prefix + "-") as temporary:
        root = Path(temporary)
        (root / "results").mkdir()
        try:
            summary["engine"] = json.loads(docker("version", "--format", "{{json .Server}}"))
            summary["kernel"] = docker("info", "--format", "{{.KernelVersion}}")
            summary["image"] = json.loads(docker(
                "image", "inspect", args.image, "--format",
                '{"id":{{json .Id}},"digests":{{json .RepoDigests}}}'
            ))
            summary["parameters"] = vars(args)
            network_created = True
            docker("network", "create", "--internal", network)
            export = prefix + "-export"
            created.append(export)
            docker("create", "--name", export, args.ca_image)
            docker("cp", export + ":" + args.ca_source, root / "public.pem")
            for name in ("mock.py", "observe.py"):
                shutil.copyfile(HERE / name, root / name)
            material = Path(args.material_dir).resolve() if args.material_dir else root
            material.mkdir(parents=True, exist_ok=True)
            if not (material / "cert.pem").exists() and not (material / "key.pem").exists():
                cert_generator = prefix + "-cert"
                created.append(cert_generator)
                docker(
                    "run", "--name", cert_generator, "--network", "none",
                    "-v", f"{material}:/probe", "--entrypoint", "openssl", args.helper_image,
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-keyout", "/probe/key.pem", "-out", "/probe/cert.pem",
                    "-subj", "/CN=mock.local",
                    "-addext", "subjectAltName=DNS:mock.local,DNS:login.microsoftonline.com,"
                    "DNS:blob.local,DNS:queue.local",
                    "-addext", "basicConstraints=critical,CA:TRUE",
                )
            if material != root:
                for name in ("cert.pem", "key.pem"):
                    shutil.copyfile(material / name, root / name)
            bundle = (root / "public.pem").read_bytes()
            if not args.untrusted:
                bundle += b"\n" + (root / "cert.pem").read_bytes()
            (root / "bundle.pem").write_bytes(bundle)
            config = configuration(
                args.outputs, args.workers, args.verify_hostname, args.buffering
            ).encode()
            (root / "probe.conf").write_bytes(config)
            summary["ca_sha256"] = hashlib.sha256(bundle).hexdigest()
            summary["config_sha256"] = hashlib.sha256(config).hexdigest()

            mock = prefix + "-mock"
            mock_args = [
                "--resources", str(args.resources),
                "--resource-host", "wrong.local" if args.wrong_hostname else "mock.local",
                "--delay", str(args.delay),
            ]
            if args.fail_identity:
                mock_args.append("--fail-identity")
            if args.split_hosts:
                mock_args.append("--split-hosts")
            created.append(mock)
            docker(
                "run", "-d", "--name", mock, "--network", network,
                "--network-alias", "mock.local",
                "--network-alias", "wrong.local",
                "--network-alias", "blob.local", "--network-alias", "queue.local",
                "--network-alias", "login.microsoftonline.com",
                "-v", f"{root}:/probe:ro",
                "--entrypoint", "python", args.helper_image, "/probe/mock.py", *mock_args,
            )
            docker(
                "exec", mock, "python", "-c",
                "import ssl,urllib.request,time\n"
                "for attempt in range(50):\n"
                " try:\n"
                "  urllib.request.urlopen('https://mock.local/health',"
                "context=ssl.create_default_context(cafile='/probe/cert.pem'),"
                "timeout=1); break\n"
                " except (OSError,ValueError): time.sleep(.1)\n"
                "else: raise RuntimeError('mock not ready')",
            )

            logger = prefix + "-logger"
            created.append(logger)
            command = ["/fluent-bit/bin/fluent-bit", "-c", "/probe/probe.conf"]
            if args.valgrind:
                command = [
                    "valgrind", "--error-exitcode=99", "--leak-check=full",
                    "--show-leak-kinds=definite,indirect",
                    "--errors-for-leak-kinds=definite,indirect",
                    "--log-file=/results/valgrind.log", *command,
                ]
            docker(
                "run", "-d", "--name", logger, "--network", network,
                "--memory", f"{args.memory}m", "--memory-swap", f"{args.memory}m",
                "--cpus", "1", "--pids-limit", "64", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--tmpfs", "/tmp:rw,size=32m",
                "-v", f"{root}:/probe:ro", "-v", f"{root / 'results'}:/results",
                "-v", f"{root / 'bundle.pem'}:{args.ca_target}:ro",
                "--entrypoint", command[0], args.image, *command[1:],
            )
            observer = prefix + "-observer"
            created.append(observer)
            docker(
                "run", "-d", "--name", observer, "--network", "none",
                "--pid", f"container:{logger}", "--cap-add", "SYS_PTRACE",
                "-v", f"{root}:/probe:ro",
                "--entrypoint", "python", args.helper_image, "/probe/observe.py",
            )
            time.sleep(2)
            observation = docker("logs", observer)
            if not observation:
                raise RuntimeError("Memory observer failed to start: " + container_logs(observer))
            first = json.loads(observation.splitlines()[0])
            if int(first["memory_max"]) != args.memory * 1024 * 1024:
                raise RuntimeError("observer is not reading the logger memory cgroup")
            if "fluent" not in first["command"] and not args.valgrind:
                raise RuntimeError(f"unexpected logger process: {first['command']}")
            summary["observer"] = first
            start = time.monotonic()
            while time.monotonic() - start < args.seconds:
                state = json.loads(docker("inspect", "--format", "{{json .State}}", logger))
                if not state["Running"]:
                    break
                observer_running = docker(
                    "inspect", "--format", "{{.State.Running}}", observer
                )
                if observer_running != "true":
                    raise RuntimeError("Memory observer stopped early: " + container_logs(observer))
                if args.stop_after_rotations:
                    rotations = rotation_counts(
                        container_logs(logger), "ingestion resources rotated successfully"
                    )
                    if (
                        len(rotations) == args.outputs
                        and min(rotations.values()) >= args.stop_after_rotations
                    ):
                        docker("stop", "--time", "30", logger, timeout=45)
                        break
                time.sleep(2)
            else:
                docker("stop", "--time", "30", logger, timeout=45)

            summary["elapsed_seconds"] = time.monotonic() - start
            summary["state"] = json.loads(docker(
                "inspect", "--format", "{{json .State}}", logger
            ))
            samples = [
                json.loads(line) for line in docker("logs", observer).splitlines()
                if '"anonymous"' in line
            ]
            if not samples:
                raise RuntimeError("observer produced no memory samples")
            summary["anonymous_peak"] = max(s["anonymous"] for s in samples)
            summary["anonymous_final"] = samples[-1]["anonymous"]
            summary["cgroup_peak"] = max(s["memory_peak"] for s in samples)
            summary["samples"] = samples

            logs = container_logs(logger)
            for name, message in [
                ("rotations", "ingestion resources rotated successfully"),
                ("blob_cleanups", "clearing up old blob HA"),
                ("queue_cleanups", "clearing up old queue HA"),
            ]:
                summary[name] = rotation_counts(logs, message)
            summary["tls_errors"] = sum(
                "certificate verify failed" in line or "certificate verification failed" in line
                for line in logs.splitlines()
            )
            mock_events = [json.loads(line) for line in docker("logs", mock).splitlines()]
            summary["requests"] = dict(collections.Counter(
                event["category"] for event in mock_events
            ))
            summary["sni"] = sorted({
                event["name"] for event in mock_events if event["category"] == "sni"
                and event["name"] is not None
            })
            if args.valgrind:
                checker = root / "results/valgrind.log"
                if not checker.exists():
                    raise RuntimeError("Valgrind did not produce its report")
                report = checker.read_text()
                output.with_suffix(".valgrind.log").write_text(report)
                summary["valgrind_clean"] = (
                    "ERROR SUMMARY: 0 errors" in report
                    and summary["state"]["ExitCode"] == 0
                )
            output.write_text(json.dumps(summary, indent=2) + "\n")
        finally:
            failures = []
            for name in reversed(created):
                result = subprocess.run(
                    ["docker", "rm", "-f", name], capture_output=True, text=True, timeout=45
                )
                if result.returncode and "No such container:" not in result.stderr:
                    failures.append(f"{name}: {result.stderr.strip()}")
            if network_created:
                result = subprocess.run(
                    ["docker", "network", "rm", network],
                    capture_output=True, text=True, timeout=45,
                )
                if result.returncode and f"network {network} not found" not in result.stderr:
                    failures.append(f"{network}: {result.stderr.strip()}")
            if failures:
                raise RuntimeError("Cleanup failed: " + "; ".join(failures))
    return summary


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--helper-image", required=True, help="Image with Python and OpenSSL")
    parser.add_argument("--ca-image", default=PUBLIC_IMAGE)
    parser.add_argument("--ca-source", default="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
    parser.add_argument("--ca-target", default="/etc/ssl/certs/ca-bundle.crt")
    parser.add_argument("--result", required=True)
    parser.add_argument("--material-dir", help="Reuse local test certificate/key for matched runs; delete afterward")
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--memory", type=int, default=512)
    parser.add_argument("--outputs", type=int, default=5)
    parser.add_argument("--resources", type=int, default=20)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--min-rotations", type=int, default=1)
    parser.add_argument("--stop-after-rotations", type=int, default=0,
                        help="Stop early once every output has this many rotations")
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("--verify-hostname", action="store_true")
    host_mode = parser.add_mutually_exclusive_group()
    host_mode.add_argument("--wrong-hostname", action="store_true")
    host_mode.add_argument("--split-hosts", action="store_true",
                           help="Use separate blob and queue hostnames to exercise SNI")
    parser.add_argument("--untrusted", action="store_true")
    parser.add_argument("--fail-identity", action="store_true")
    parser.add_argument("--buffering", action="store_true")
    parser.add_argument("--valgrind", action="store_true", default=os.getenv("VALGRIND") == "1")
    args = parser.parse_args()
    if min(args.seconds, args.memory, args.outputs, args.resources,
           args.workers, args.min_rotations) <= 0:
        parser.error("limits and counts must be positive")
    if args.delay < 0 or args.stop_after_rotations < 0:
        parser.error("delay and stop-after-rotations cannot be negative")
    return args


if __name__ == "__main__":
    options = arguments()
    result = run_case(options)
    print(json.dumps({key: value for key, value in result.items() if key != "samples"}, indent=2))
    if result["state"]["OOMKilled"]:
        raise SystemExit(137)
    if result["state"]["ExitCode"] != 0 or result.get("valgrind_clean") is False:
        raise SystemExit(1)
    if result["requests"].get("unexpected") or result["requests"].get("unexpected-command"):
        raise SystemExit("Unexpected mock requests; inspect the saved result")
    if options.untrusted or options.wrong_hostname:
        if (
            not result["tls_errors"]
            or result["requests"].get("blob")
            or result["requests"].get("queue")
        ):
            raise SystemExit("Failed certificate rejection check; inspect the saved result")
    else:
        if (
            not result["requests"].get("blob")
            or not result["requests"].get("queue")
            or len(result["rotations"]) != options.outputs
            or min(result["rotations"].values(), default=0) < options.min_rotations
        ):
            raise SystemExit("Failed ingestion/rotation coverage; inspect the saved result")
