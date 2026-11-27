import json

from utils.data_utils import read_file
from utils.test_service import FluentBitTestService


def test_out_stdout_json_preserves_invalid_utf8(tmp_path):
    cases = [
        (b"\xc0\x80", "\ue0c0\ue080"),
        (b"\xe0\x9f\xbf", "\ue0e0\ue09f\ue0bf"),
        (b"\xf0\x8f\xbf\xbf", "\ue0f0\ue08f\ue0bf\ue0bf"),
        (b"\xe2\x82", "\ue0e2\ue082"),
        (b"\xe2A", "\ue0e2A"),
        (b"a\xfe\xffb", "a\ue0fe\ue0ffb"),
        (b"\xc2\x80\xe0\xa0\x80\xf0\x90\x80\x80", "\u0080\u0800\U00010000"),
    ]
    source = tmp_path / "input.log"
    source.write_bytes(b"\n".join(raw for raw, _ in cases) + b"\n")
    config = tmp_path / "pipeline.yaml"
    config.write_text(f"""service:
  flush: 1
  grace: 1
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
pipeline:
  inputs:
    - name: tail
      path: {source}
      read_from_head: true
      tag: utf8
  outputs:
    - name: stdout
      match: '*'
      format: json_lines
""")
    service = FluentBitTestService(str(config))

    def records():
        return [json.loads(line)["log"]
                for line in read_file(service.flb.log_file).splitlines()
                if line.startswith('{')]

    try:
        service.start()
        actual = service.wait_for_condition(
            lambda: records() if len(records()) == len(cases) else None,
            timeout=30,
            description="all UTF-8 records in JSON output",
        )
        assert actual == [expected for _, expected in cases]
    finally:
        service.stop()
