"""The generic MessagePack-to-JSON writer must keep decimal points in JSON."""
import json
import os
import shutil
import subprocess
import sys

import pytest

import yaml

from utils.data_utils import read_file
from utils.test_service import FluentBitTestService


@pytest.fixture(params=["C", "de_DE.UTF-8"])
def numeric_locale_env(tmp_path, request):
    if request.param == "C":
        return {}
    compiler = shutil.which("cc")
    localedef = shutil.which("localedef")
    if sys.platform != "linux" or not compiler or not localedef:
        pytest.skip("comma-decimal embedding test requires Linux, cc, and localedef")
    locales = tmp_path / "locales"
    locales.mkdir()
    result = subprocess.run([localedef, "-i", "de_DE", "-f", "UTF-8",
                             str(locales / "de_DE.UTF-8")], capture_output=True, text=True)
    if result.returncode:
        pytest.skip(f"cannot generate de_DE.UTF-8 locale: {result.stderr.strip()}")
    source = tmp_path / "numeric_locale.c"
    source.write_text(r"""
#include <locale.h>
#include <stdlib.h>
__attribute__((constructor)) static void select_numeric_locale(void)
{
    const char *path = getenv("FLB_TEST_LOCPATH");
    if (path == NULL || setenv("LOCPATH", path, 1) != 0 ||
        setlocale(LC_NUMERIC, "de_DE.UTF-8") == NULL) {
        abort();
    }
    /* Keep private locale search paths out of unrelated library initialization. */
    unsetenv("LOCPATH");
}
""")
    library = tmp_path / "numeric_locale.so"
    subprocess.run([compiler, "-shared", "-fPIC", str(source), "-o", str(library)], check=True)
    preload = str(library)
    if os.environ.get("LD_PRELOAD"):
        preload += ":" + os.environ["LD_PRELOAD"]
    return {"LD_PRELOAD": preload, "FLB_TEST_LOCPATH": str(locales)}


def test_stdout_json_fractional_numbers(tmp_path, numeric_locale_env):
    config = {
        "service": {"flush": 1, "grace": 1, "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "tag": "decimal", "samples": 1,
                        "dummy": '{"marker":"decimal-test","fraction":1.5,"negative":-2.25,"whole":1.0}'}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}],
        },
    }
    path = tmp_path / "decimal.yaml"
    path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(path), extra_env=numeric_locale_env)
    service.start()
    try:
        def read_record():
            for line in read_file(service.flb.log_file).splitlines():
                if line.startswith("{") and "decimal-test" in line:
                    return json.loads(line)
        record = service.wait_for_condition(read_record, timeout=10, description="JSON decimal record")
        assert record["fraction"] == 1.5
        assert record["negative"] == -2.25
        assert record["whole"] == 1.0
    finally:
        service.stop()
