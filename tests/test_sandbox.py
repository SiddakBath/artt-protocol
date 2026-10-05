import pytest
from rt.bundle import CAPS
from rt.runner import submit


def test_os_filesystem_process_and_mount_restrictions(make_bundle, tmp_path, verdict):
    code = '''import ctypes, errno, os
def run(api):
    assert not os.path.exists('/mnt/c')
    assert not os.path.exists('/proc')
    assert not os.listdir('/home')
    for path in ('/bundle/judge/main.py', '/usr/test-write', '/etc/test-write'):
        try:
            open(path, 'w')
        except OSError as exc:
            assert exc.errno in (errno.EROFS, errno.EACCES)
        else:
            raise AssertionError('writable host/bundle')
    open('/tmp/private-file','w').write('temporary secret')
    try:
        os.fork()
    except OSError as exc:
        assert exc.errno == errno.EPERM
    else:
        raise AssertionError('fork allowed')
    lib = ctypes.CDLL(None, use_errno=True)
    assert lib.mount(None, b'/tmp', None, 0, None) == -1
    assert ctypes.get_errno() == errno.EPERM
    api.emit(VERDICT)
'''.replace("VERDICT", repr(verdict))
    private = tmp_path / "temp-parent"
    private.mkdir()
    assert submit(make_bundle(code), tmp_path / "log", temp_parent=private)["kind"] == "accepted"
    assert list(private.iterdir()) == []


def test_timeout_oom_and_call_cap(make_bundle, tmp_path):
    root = make_bundle("def run(api):\n    while True: pass\n", resources={**CAPS, "max_seconds": 1})
    assert submit(root, tmp_path / "log")["error_code"] == "timeout"
    root = make_bundle("def run(api):\n    x = bytearray(512 * 1024 * 1024)\n", resources={**CAPS, "max_ram_mb": 64})
    assert submit(root, tmp_path / "log")["error_code"] == "oom"
    root = make_bundle('def run(api):\n    api.complete([{"role":"user","content":"SECRET"}])\n    api.complete([{"role":"user","content":"SECRET"}])\n',
                       resources={**CAPS, "max_complete_calls": 1})
    assert submit(root, tmp_path / "log")["error_code"] == "complete_limit"
    assert "SECRET" not in (tmp_path / "log").read_text()


def test_print_stderr_and_oversized_ipc_do_not_leak(make_bundle, tmp_path, verdict):
    root = make_bundle("import sys\ndef run(api):\n    print('SECRET-PRINT')\n    print('SECRET-STDERR',file=sys.stderr)\n    api.emit(" + repr(verdict) + ")\n")
    assert submit(root, tmp_path / "log")["kind"] == "accepted"
    root = make_bundle('def run(api):\n    api.emit({"text": "SECRET" * 30000})\n')
    assert submit(root, tmp_path / "log")["kind"] == "error"
    assert "SECRET" not in (tmp_path / "log").read_text()
