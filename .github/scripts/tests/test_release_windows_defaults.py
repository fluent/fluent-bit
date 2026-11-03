"""Check the Nano Server exporter override against the real CMake settings."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class WindowsExporterDefaultsTests(unittest.TestCase):
    def check_option(self, windows, defaults, explicit, expected):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "check.cmake"
            override = ""
            if explicit is not None:
                override = (
                    f'set(FLB_IN_WINDOWS_EXPORTER_METRICS {explicit} '
                    'CACHE BOOL "Explicit caller option")\n'
                )
            script.write_text(
                'cmake_minimum_required(VERSION 3.12)\n'
                f'set(WIN32 {windows})\n'
                f'set(FLB_WINDOWS_DEFAULTS {defaults})\n'
                'set(CMAKE_SIZEOF_VOID_P 8)\n'
                f'set(CMAKE_CURRENT_SOURCE_DIR "{ROOT.as_posix()}")\n'
                f'set(CMAKE_CURRENT_BINARY_DIR "{Path(directory).as_posix()}")\n'
                'file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/src")\n'
                # The test does not compile parsers; stub only tool discovery.
                'function(find_package name)\n'
                '  set(${name}_FOUND TRUE PARENT_SCOPE)\n'
                'endfunction()\n'
                + override
                + 'include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/plugins_options.cmake")\n'
                + 'if(WIN32)\n'
                + '  include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/windows-setup.cmake")\n'
                + 'endif()\n'
                + f'if(({expected} AND NOT FLB_IN_WINDOWS_EXPORTER_METRICS) OR '
                + f'(NOT {expected} AND FLB_IN_WINDOWS_EXPORTER_METRICS))\n'
                + '  message(FATAL_ERROR "Unexpected exporter setting: ${FLB_IN_WINDOWS_EXPORTER_METRICS}")\n'
                + 'endif()\n',
                encoding="utf-8",
            )
            result = subprocess.run(
                ["cmake", "-P", str(script)], capture_output=True, text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_nano_explicit_off_survives_windows_defaults(self):
        self.check_option("ON", "ON", "OFF", "OFF")

    def test_windows_exporter_enabled_by_default(self):
        self.check_option("ON", "ON", None, "ON")

    def test_windows_explicit_on_survives_defaults(self):
        self.check_option("ON", "ON", "ON", "ON")

    def test_windows_without_defaults_does_not_enable_exporter(self):
        self.check_option("ON", "OFF", None, "OFF")

    def test_non_windows_does_not_enable_exporter(self):
        self.check_option("OFF", "ON", None, "OFF")
