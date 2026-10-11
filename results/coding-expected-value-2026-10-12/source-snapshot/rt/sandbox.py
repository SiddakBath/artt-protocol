"""Mandatory Linux namespaces and seccomp. No fallback, no hardware claim."""
from dataclasses import dataclass
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time
from .schema import canonical, strict_json, validate

FRAME_LIMIT = 65536


@dataclass
class Result:
    verdict: dict | None = None
    error: str | None = None
    n_calls: int = 0


def execute(bundle, private, manifest, model, experimental_validator=None):
    if sys.platform != "linux":
        raise RuntimeError("Linux namespace sandbox required; use WSL.")
    resources = manifest["resources"]
    worker = Path(__file__).with_name("worker.py").resolve()
    launcher = worker.parent.parent / ".build/isolate"
    if not launcher.is_file():
        raise RuntimeError("Run python3 -m rt.build_sandbox first.")
    root = Path(private) / "root"
    root.mkdir()
    env = {"HOME": "/home", "TMPDIR": "/tmp", "RT_SCHEMA": manifest["verdict_schema_id"]}
    proc = subprocess.Popen(["/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net",
                             "--ipc", "--uts", "--pid", "--fork", "--kill-child", str(launcher), str(root),
                             str(Path(bundle).resolve()), str(worker), str(resources["max_ram_mb"])],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=env, cwd=private, start_new_session=True)
    frames = queue.Queue(maxsize=8)
    stop = threading.Event()
    def reader():
        try:
            while not stop.is_set():
                raw = proc.stdout.readline(FRAME_LIMIT + 1)
                value = strict_json(raw) if raw and len(raw) <= FRAME_LIMIT and raw.endswith(b"\n") else None
                while not stop.is_set():
                    try:
                        frames.put(value, timeout=0.1)
                        break
                    except queue.Full:
                        continue
                if value is None:
                    return
        except (ValueError, OSError):
            if not stop.is_set():
                try:
                    frames.put(None, timeout=0.2)
                except queue.Full:
                    pass
    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    deadline = time.monotonic() + resources["max_seconds"]
    result = Result()
    emitted = False
    def reply(value):
        proc.stdin.write(canonical(value) + b"\n")
        proc.stdin.flush()
    try:
        ready = frames.get(timeout=max(0.001, deadline - time.monotonic()))
        if ready != {"op": "ready"}:
            result.error = "runtime_exception"
            return result
        reply({"go": True})
        while True:
            request = frames.get(timeout=max(0.001, deadline - time.monotonic()))
            if type(request) is not dict:
                result.error = "runtime_exception"
                break
            op = request.get("op")
            if op == "complete" and set(request) == {"op", "messages"}:
                if result.n_calls >= resources["max_complete_calls"]:
                    result.error = "complete_limit"
                    break
                messages = request["messages"]
                if (type(messages) is not list or not 1 <= len(messages) <= 64 or
                    any(type(m) is not dict or set(m) != {"role", "content"} or
                        m["role"] not in ("user", "system", "assistant") or
                        type(m["content"]) is not str for m in messages)):
                    result.error = "runtime_exception"
                    break
                response = queue.Queue(maxsize=1)
                def call(current=messages):
                    try:
                        response.put((True, model.complete(current)))
                    except BaseException:
                        response.put((False, None))
                threading.Thread(target=call, daemon=True).start()
                ok, text = response.get(timeout=max(0.001, deadline - time.monotonic()))
                if not ok or type(text) is not str or len(canonical({"value": text})) > FRAME_LIMIT:
                    result.error = "runtime_exception"
                    break
                result.n_calls += 1
                reply({"value": text})
                text = messages = None
            elif op == "emit" and set(request) == {"op", "verdict"}:
                if emitted:
                    result.error = "double_emit"
                    reply({"error": "double_emit"})
                    break
                emitted = True
                try:
                    result.verdict = (experimental_validator(request["verdict"]) if experimental_validator else
                        validate(request["verdict"], resources["max_complete_calls"], manifest["verdict_schema_id"], proposal=True))
                except (ValueError, TypeError, KeyError):
                    result.error = "bad_verdict"
                    break
                reply({"value": None})
            elif op == "done" and set(request) == {"op", "error"}:
                error = request["error"]
                if error not in (None, "runtime_exception", "oom", "socket_attempt"):
                    error = "runtime_exception"
                result.error = error or (None if emitted else "no_emit")
                proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                if proc.returncode != 0 and result.error is None:
                    result.error = "runtime_exception"
                break
            else:
                result.error = "runtime_exception"
                break
    except (queue.Empty, subprocess.TimeoutExpired):
        result.error = "timeout"
    except (OSError, ValueError, TypeError):
        result.error = "runtime_exception"
    finally:
        stop.set()
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        proc.stdin.close()
        thread.join(timeout=1)
        proc.stdout.close()
        if result.error:
            result.verdict = None
    return result
