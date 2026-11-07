"""Classic includes must prefer the main configuration directory."""

from pathlib import Path

from utils.test_service import FluentBitTestService


def test_classic_include_prefers_config_directory(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    working_dir = tmp_path / "working"
    config_dir.mkdir()
    working_dir.mkdir()
    (config_dir / "input.conf").write_text(
        '[INPUT]\n    Name dummy\n    Tag include.test\n'
        '    Dummy {"message":"config-selected"}\n    Samples 1\n')
    (working_dir / "input.conf").write_text(
        '[INPUT]\n    Name dummy\n    Tag include.test\n'
        '    Dummy {"message":"working-selected"}\n    Samples 1\n')
    config = config_dir / "fluent-bit.conf"
    config.write_text(
        '[SERVICE]\n    Flush 0.2\n    Grace 1\n    HTTP_Server On\n'
        '    HTTP_Port ${FLUENT_BIT_HTTP_MONITORING_PORT}\n'
        '@INCLUDE input.conf\n'
        '[OUTPUT]\n    Name stdout\n    Match *\n    Format json_lines\n')

    monkeypatch.chdir(working_dir)
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(
            lambda: "config-selected" in Path(service.flb.log_file).read_text(),
            timeout=15,
        )
        assert "working-selected" not in Path(service.flb.log_file).read_text()
    finally:
        service.stop()


def test_classic_relative_main_config_is_not_resolved_again(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    nested_dir = config_dir / "config"
    nested_dir.mkdir(parents=True)
    (config_dir / "main.conf").write_text(
        '[SERVICE]\n    Flush 0.2\n    Grace 1\n    HTTP_Server On\n'
        '    HTTP_Port ${FLUENT_BIT_HTTP_MONITORING_PORT}\n'
        '@INCLUDE input.conf\n'
        '[OUTPUT]\n    Name stdout\n    Match *\n    Format json_lines\n')
    (config_dir / "input.conf").write_text(
        '[INPUT]\n    Name dummy\n    Tag include.test\n'
        '    Dummy {"message":"requested-main-selected"}\n    Samples 1\n')
    # Re-resolving config/main.conf against its own directory selects this file.
    (nested_dir / "main.conf").write_text('[INPUT]\n    Name nonexistent_shadow_plugin\n')

    monkeypatch.chdir(tmp_path)
    service = FluentBitTestService(str(Path("config") / "main.conf"))
    try:
        service.start()
        service.wait_for_condition(
            lambda: "requested-main-selected" in Path(service.flb.log_file).read_text(),
            timeout=15,
        )
    finally:
        service.stop()
