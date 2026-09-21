"""Linux host read-only preflight evidence probe.

Collects a machine-readable environment baseline for later native
install/RTSP/24h acceptance runs: OS identity, Python, and tool
discoverability via ``shutil.which``.  Strictly read-only: no subprocess,
no network, no installs, no service control, no file or config changes.
Presence of a tool is reported as ``available`` only -- it never implies
version support, service health, RTSP decodability, or any acceptance
outcome.  ``host_gate_passed`` and ``release_gate_passed`` stay null.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from datetime import datetime, timezone

SCHEMA = "scam.linux-host-probe/v1"
TOOLS = ("ffmpeg", "ffprobe", "systemctl")
UNEVALUATED_GATES = [
    "dependency_installation",
    "systemd_service_runtime",
    "real_rtsp_streams",
    "dual_stream_isolation",
    "soak_24h",
    "resource_plateau",
]


def _utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _observe_tool(name, which_fn):
    """Report tool discoverability only; never execute the tool."""
    found = which_fn(name)
    if found is not None and not isinstance(found, str):
        found = str(found)
    return {"name": name, "available": found is not None, "path": found}


def collect_observation(*, system=None, platform_platform=None,
                        python_version=None, python_executable=None,
                        which_fn=None):
    """Collect one read-only host observation.

    All inputs are injectable so tests can simulate Linux/non-Linux hosts
    and tool discovery without touching the real machine.
    """
    system_value = str(system if system is not None else sys.platform)
    description = (platform_platform if platform_platform is not None
                   else platform.platform())
    version = (python_version if python_version is not None
               else sys.version.split()[0])
    executable = (python_executable if python_executable is not None
                  else sys.executable)
    finder = which_fn if which_fn is not None else shutil.which

    return {
        "schema": SCHEMA,
        "kind": "host_preflight",
        "observed_at": _utc_now(),
        "platform_system": system_value,
        "platform_platform": description,
        "python_version": version,
        "python_executable": executable,
        # Python 3 documents ``sys.platform == 'linux'`` for Linux.
        # Do not let an arbitrary look-alike value such as ``linux-proxy``
        # upgrade an observation to native-host evidence.
        "native_linux": system_value == "linux",
        "tools": [_observe_tool(name, finder) for name in TOOLS],
        "host_gate_passed": None,
        "release_gate_passed": None,
        "unevaluated_gates": list(UNEVALUATED_GATES),
        "host_gate_note": (
            "Read-only environment baseline only; availability does not "
            "imply version support, service health, RTSP decodability or "
            "any acceptance outcome."),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="只读采集Linux主机预检证据基线（零子进程/零网络/不修改任何文件）")
    parser.parse_args(argv)
    try:
        observation = collect_observation()
    except Exception as exc:
        json.dump(
            {"schema": SCHEMA, "kind": "host_preflight_error",
             "integrity_passed": False, "error": f"{type(exc).__name__}: {exc}",
             "host_gate_passed": None, "release_gate_passed": None},
            sys.stderr, ensure_ascii=False)
        sys.stderr.write("\n")
        return 1
    print(json.dumps(observation, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
