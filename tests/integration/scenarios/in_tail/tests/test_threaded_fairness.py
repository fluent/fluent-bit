"""Keep flushing while a threaded producer outruns main-thread filtering."""


from test_in_tail_001 import Service, flatten_records
from server.http_server import data_storage


def test_threaded_tail_flushes_before_backlog_drains(tmp_path):
    log_path = tmp_path / "input.log"
    total_records = 32768
    log_path.touch()

    # A fixed CPU cost makes overload reproducible without machine-specific regexes.
    script_path = tmp_path / "slow.lua"
    script_path.write_text(
        "function slow(tag, timestamp, record)\n"
        "  local deadline = os.clock() + 0.001\n"
        "  while os.clock() < deadline do end\n"
        "  return 0, timestamp, record\n"
        "end\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "fairness.yaml"
    config_path.write_text(
        f"""service:
  flush: 0.2
  grace: 1
  log_level: error
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
  storage.path: {tmp_path / 'storage'}
  storage.max_chunks_up: 8
pipeline:
  inputs:
    - name: tail
      path: {log_path}
      tag: fairness
      read_from_head: true
      threaded: true
      buffer_chunk_size: 512
      buffer_max_size: 512
      static_batch_size: 512
      event_batch_size: 512
      thread.ring_buffer.capacity: 256
      thread.ring_buffer.window: 10
      storage.type: filesystem
      storage.pause_on_chunks_overlimit: false
  filters:
    - name: lua
      match: '*'
      script: {script_path}
      call: slow
  outputs:
    - name: http
      match: '*'
      host: 127.0.0.1
      port: ${{TEST_SUITE_HTTP_PORT}}
      uri: /data
      format: json
      json_date_key: false
      workers: 1
      storage.total_limit_size: 128M
      retry_limit: false
    - name: null
      match: '*'
""",
        encoding="utf-8",
    )
    service = Service(str(config_path), tail_path=log_path, db_path=tmp_path / "tail.db")
    try:
        service.start()
        log_path.write_text(("x" * 240 + "\n") * total_records, encoding="utf-8")
        # Two separate flushes must complete well before the 32 CPU-second backlog.
        service.service.wait_for_condition(
            lambda: len(data_storage["requests"]) >= 2,
            timeout=15,
            interval=0.1,
            description="continued output while threaded tail is overloaded",
        )
        records = flatten_records(data_storage["payloads"])
        assert 0 < len(records) < total_records
        assert all(record["log"] == "x" * 240 for record in records)
    finally:
        service.stop()
