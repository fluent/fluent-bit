"""Opt-in tests against disposable, actual Confluent Kafka and Schema Registry processes.

Set FLB_REAL_CONFLUENT_HOME to an unpacked Confluent Community distribution and
JAVA_HOME to a compatible runtime. No externally managed cluster is contacted.
"""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

import pytest
import requests
import yaml

from utils.network import find_available_port
from utils.test_service import FluentBitTestService
from test_out_kafka_schema_registry import ROOT, DETAILS, EVENT


def _wait_ready(process, check, log, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(f"Confluent service exited: {log.read_text()[-8000:]}")
        try:
            if check():
                return
        except (OSError, requests.RequestException):
            pass
        time.sleep(0.2)
    pytest.fail(f"Confluent service did not become ready: {log.read_text()[-8000:]}")


def _tcp_ready(port):
    with socket.create_connection(("127.0.0.1", port), timeout=1):
        return True


@pytest.fixture(scope="module")
def confluent(tmp_path_factory):
    home_setting = os.environ.get("FLB_REAL_CONFLUENT_HOME")
    if not home_setting:
        pytest.skip("set FLB_REAL_CONFLUENT_HOME to run actual Confluent service tests")
    home = Path(home_setting).resolve()
    work = tmp_path_factory.mktemp("confluent")
    env = os.environ.copy()
    env.update(KAFKA_HEAP_OPTS="-Xms256m -Xmx512m", SCHEMA_REGISTRY_HEAP_OPTS="-Xms256m -Xmx512m",
               LOG_DIR=str(work / "logs"))
    cert_dir = (Path(__file__).parent / "../../in_splunk/certificate").resolve()
    certificate = cert_dir / "certificate.pem"
    keystore = work / "registry.p12"
    truststore = work / "truststore.p12"
    subprocess.run(["openssl", "pkcs12", "-export", "-in", str(certificate),
                    "-inkey", str(cert_dir / "private_key.pem"), "-out", str(keystore),
                    "-name", "registry", "-passout", "pass:test-password"], check=True, env=env)
    keytool = str(Path(env["JAVA_HOME"]) / "bin/keytool") if env.get("JAVA_HOME") else "keytool"
    subprocess.run([keytool, "-importcert", "-noprompt", "-alias", "registry", "-file", str(certificate),
                    "-keystore", str(truststore), "-storetype", "PKCS12", "-storepass", "test-password"],
                   check=True, env=env, capture_output=True)
    broker_port = find_available_port()
    controller_port = find_available_port(broker_port + 1)
    registry_port = find_available_port(controller_port + 1)
    broker = f"127.0.0.1:{broker_port}"
    registry = f"https://127.0.0.1:{registry_port}"
    kafka_config = work / "kafka.properties"
    kafka_config.write_text(f"""process.roles=broker,controller
node.id=1
controller.quorum.voters=1@127.0.0.1:{controller_port}
listeners=PLAINTEXT://127.0.0.1:{broker_port},CONTROLLER://127.0.0.1:{controller_port}
advertised.listeners=PLAINTEXT://{broker}
inter.broker.listener.name=PLAINTEXT
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
log.dirs={work / 'kafka-data'}
num.partitions=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
""")
    registry_config = work / "registry.properties"
    registry_config.write_text(f"""listeners={registry}
host.name=127.0.0.1
inter.instance.protocol=https
kafkastore.bootstrap.servers=PLAINTEXT://{broker}
kafkastore.topic.replication.factor=1
ssl.keystore.location={keystore}
ssl.keystore.password=test-password
ssl.key.password=test-password
ssl.keystore.type=PKCS12
ssl.truststore.location={truststore}
ssl.truststore.password=test-password
ssl.truststore.type=PKCS12
""")
    cluster = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode().rstrip("=")
    result = subprocess.run([str(home / "bin/kafka-storage"), "format", "-t", cluster,
                             "-c", str(kafka_config)], env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    processes = []
    logs = []
    try:
        for command, config, log_name, ready in [
            ("kafka-server-start", kafka_config, "kafka.log", lambda: _tcp_ready(broker_port)),
            ("schema-registry-start", registry_config, "registry.log",
             lambda: requests.get(registry + "/subjects", verify=str(certificate), timeout=1).status_code == 200),
        ]:
            log_path = work / log_name
            log = log_path.open("w")
            logs.append(log)
            process = subprocess.Popen([str(home / "bin" / command), str(config)], env=env,
                                       stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            _wait_ready(process, ready, log_path)
        yield dict(home=home, work=work, env=env, broker=broker, registry=registry,
                   certificate=certificate, truststore=truststore)
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        for log in logs:
            log.close()


def _register(confluent, subject, schema, schema_type, references=None):
    response = requests.post(confluent["registry"] + f"/subjects/{subject}/versions",
                             json={"schema": schema, "schemaType": schema_type, "references": references or []},
                             verify=str(confluent["certificate"]), timeout=15)
    response.raise_for_status()
    return response.json()["id"]


@pytest.mark.parametrize("format_name", ["avro", "protobuf"])
def test_actual_confluent_registry_and_consumer(confluent, tmp_path, format_name):
    topic = f"flb-{format_name}-conformance"
    event = {"message": "hello avro", "source": "dummy"}
    if format_name == "protobuf":
        _register(confluent, "details-value", DETAILS, "PROTOBUF")
        schema = ROOT
        schema_id = _register(confluent, topic + "-value", schema, "PROTOBUF", [
            {"name": "details.proto", "subject": "details-value", "version": 1}])
        event = EVENT
    else:
        schema = json.dumps({"type": "record", "name": "Event", "fields": [
            {"name": "message", "type": "string"}, {"name": "source", "type": "string"}]})
        schema_id = _register(confluent, topic + "-value", schema, "AVRO")
    fetched = requests.get(confluent["registry"] + f"/subjects/{topic}-value/versions/1",
                           verify=str(confluent["certificate"]), timeout=10).json()
    assert fetched["id"] == schema_id
    assert fetched["schema"]
    result = subprocess.run([str(confluent["home"] / "bin/kafka-topics"), "--bootstrap-server",
                             confluent["broker"], "--create", "--topic", topic, "--partitions", "1",
                             "--replication-factor", "1"], env=confluent["env"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    output = {"name": "kafka", "match": "*", "brokers": confluent["broker"], "topics": topic,
              "format": format_name, "schema_registry_url": confluent["registry"],
              "schema_registry_subject": topic + "-value", "schema_registry_version": "1",
              "tls": "on", "tls.verify": "on", "tls.ca_file": str(confluent["certificate"])}
    if format_name == "protobuf":
        output["protobuf_message"] = "registry.Envelope.Event"
    config = {"service": {"flush": 1, "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
              "pipeline": {"inputs": [{"name": "dummy", "samples": 3, "dummy": json.dumps(event)}],
                           "outputs": [output]}}
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    service.start()
    try:
        command = [str(confluent["home"] / f"bin/kafka-{format_name}-console-consumer"),
                   "--bootstrap-server", confluent["broker"], "--topic", topic, "--from-beginning",
                   "--max-messages", "3", "--timeout-ms", "30000",
                   "--property", f"schema.registry.url={confluent['registry']}",
                   "--property", f"schema.registry.ssl.truststore.location={confluent['truststore']}",
                   "--property", "schema.registry.ssl.truststore.password=test-password",
                   "--property", "schema.registry.ssl.truststore.type=PKCS12"]
        result = subprocess.run(command, env=confluent["env"], capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        assert len(records) == 3, result.stdout + result.stderr
        assert records == [event] * 3
    finally:
        service.stop()


def test_baseline_binary_lacks_protobuf_registry_support(confluent, tmp_path, monkeypatch, record_property):
    baseline = os.environ.get("FLB_SCHEMA_BASELINE_BINARY")
    if not baseline:
        pytest.skip("set FLB_SCHEMA_BASELINE_BINARY to reproduce the existing Avro-only registry gap")
    from test_out_kafka_001 import _wait_for_log_text
    from utils.fluent_bit_manager import FluentBitStartupError

    _register(confluent, "baseline-protobuf-value", 'syntax="proto3"; message Event { string message = 1; }',
              "PROTOBUF")
    config = {
        "service": {"flush": 1, "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "samples": 1, "dummy": '{"message":"baseline"}'}],
            "outputs": [{"name": "kafka", "match": "*", "brokers": confluent["broker"],
                         "topics": "baseline-rejected", "format": "avro",
                         "schema_registry_url": confluent["registry"],
                         "schema_registry_subject": "baseline-protobuf-value", "schema_registry_version": "1",
                         "tls": "on", "tls.verify": "on", "tls.ca_file": str(confluent["certificate"])}],
        },
    }
    path = tmp_path / "baseline.yaml"
    path.write_text(yaml.safe_dump(config))
    monkeypatch.setenv("FLUENT_BIT_BINARY", baseline)
    service = FluentBitTestService(str(path))
    try:
        service.start()
    except FluentBitStartupError:
        log = Path(service.flb.log_file).read_text()
        assert "unknown configuration property 'schema_registry_" in log
        record_property("baseline_gap", "binary built without registry serializer support")
        return
    try:
        _wait_for_log_text(service.flb.log_file, "unsupported Schema Registry schemaType 'PROTOBUF'", timeout=30)
        record_property("baseline_gap", "Avro-only registry parser rejects PROTOBUF")
    finally:
        service.stop()
