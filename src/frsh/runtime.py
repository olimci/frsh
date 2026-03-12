import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROCESS_WAIT_TIMEOUT = 1.0
STARTUP_POLL_INTERVAL = 0.1


def which(binary):
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(path) / binary
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def is_executable_available(binary):
    return Path(binary).exists() or which(binary) is not None


def stop_process(proc, *, force):
    if proc is None or proc.poll() is not None:
        return

    try:
        if force:
            proc.kill()
        else:
            proc.terminate()
        proc.wait(timeout=PROCESS_WAIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=PROCESS_WAIT_TIMEOUT)
    except ProcessLookupError:
        pass


def cleanup_temp_file(temp_file):
    if temp_file is None:
        return

    try:
        name = temp_file.name
        temp_file.close()
        if os.path.exists(name):
            os.unlink(name)
    except OSError:
        pass


def create_temp_file(*, mode, suffix, prefix):
    temp_file = tempfile.NamedTemporaryFile(
        mode=mode,
        suffix=suffix,
        prefix=prefix,
        delete=False,
    )
    temp_file.flush()
    return temp_file


def read_process_output(log_file):
    if log_file is None:
        return ""
    log_file.seek(0)
    return log_file.read()


def wait_for_process_startup(
    proc,
    *,
    startup_wait,
    error_label,
    log_file,
    error_text,
):
    deadline = time.monotonic() + startup_wait
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(STARTUP_POLL_INTERVAL)

    if proc.poll() is None:
        return True

    output = read_process_output(log_file)
    print(error_text(f"{error_label} failed to start.\n"), file=sys.stderr)
    print(output or "(no log output)", file=sys.stderr)
    return False
