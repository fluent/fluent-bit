"""Runs outside the logger cgroup, sharing only its PID namespace."""

import json
import pathlib
import time


process = pathlib.Path("/proc/1")
cgroup = process / "root/sys/fs/cgroup"
print(json.dumps({
    "command": (process / "comm").read_text().strip(),
    "cgroup": (process / "cgroup").read_text().strip(),
    "memory_max": (cgroup / "memory.max").read_text().strip(),
}), flush=True)
while process.exists():
    try:
        rollup = (process / "smaps_rollup").read_text()
        anonymous = next(
            int(line.split()[1]) * 1024
            for line in rollup.splitlines() if line.startswith("Anonymous:")
        )
        print(json.dumps({
            "time": time.monotonic(),
            "anonymous": anonymous,
            "memory_current": int((cgroup / "memory.current").read_text()),
            "memory_peak": int((cgroup / "memory.peak").read_text()),
            "memory_events": (cgroup / "memory.events").read_text().strip(),
        }), flush=True)
    except (FileNotFoundError, ProcessLookupError):
        break
    time.sleep(1)
