import pytest
from rt.runner import submit


@pytest.mark.parametrize("statement", [
    'import socket; socket.create_connection(("1.1.1.1", 80), timeout=1)',
    'import urllib.request; urllib.request.urlopen("https://example.com", timeout=1)',
    'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)',
    'import socket; socket.getaddrinfo("example.com", 80)',
])
def test_network_fails_and_never_enters_log(statement, make_bundle, tmp_path):
    root = make_bundle("def run(api):\n    " + statement + "\n")
    path = tmp_path / "log.jsonl"
    entry = submit(root, path)
    assert (entry["kind"], entry["error_code"]) == ("error", "socket_attempt")
    raw = path.read_text()
    assert "1.1.1.1" not in raw and "example.com" not in raw


def test_native_socket_syscalls_denied_by_kernel(make_bundle, tmp_path, verdict):
    code = '''import ctypes, errno
def run(api):
    lib = ctypes.CDLL(None, use_errno=True)
    assert lib.socket(2, 1, 0) == -1
    assert ctypes.get_errno() == errno.EPERM
    assert lib.syscall(41, 2, 1, 0) == -1  # x86_64 socket syscall, bypass Python hooks
    assert ctypes.get_errno() == errno.EPERM
    api.emit(VERDICT)
'''.replace("VERDICT", repr(verdict))
    entry = submit(make_bundle(code), tmp_path / "log.jsonl")
    assert entry["kind"] == "accepted"
