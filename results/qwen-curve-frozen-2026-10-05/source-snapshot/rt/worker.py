"""Runs after namespace/chroot isolation; seccomp is installed before judge code."""
import ctypes
import errno
import importlib
import json
import os
from pathlib import Path
import resource
import socket
import sys
import urllib.request


def lock_syscalls():
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7FFF0000)
    if not context:
        raise RuntimeError("seccomp_unavailable")
    forbidden = ("socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
                 "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
                 "mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
                 "fsopen", "fsconfig", "fsmount", "move_mount", "open_tree", "mount_setattr",
                 "open_by_handle_at", "ptrace", "process_vm_readv", "process_vm_writev",
                 "bpf", "perf_event_open", "keyctl", "add_key", "request_key",
                 "clone", "clone3", "fork", "vfork", "execve", "execveat",
                 "io_uring_setup", "io_uring_enter", "io_uring_register", "userfaultfd",
                 "shmget", "shmat", "shmctl", "semget", "semop", "semtimedop", "semctl",
                 "msgget", "msgsnd", "msgrcv", "msgctl", "pidfd_open", "pidfd_getfd",
                 "inotify_init", "inotify_init1", "fanotify_init",
                 "reboot", "kexec_load", "init_module", "finit_module", "delete_module")
    try:
        for name in forbidden:
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number >= 0 and lib.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0) != 0:
                raise RuntimeError("seccomp_unavailable")
        if lib.seccomp_load(context) != 0:
            raise RuntimeError("seccomp_unavailable")
    finally:
        lib.seccomp_release(context)


def main():
    bundle, private = Path(sys.argv[1]), Path(sys.argv[2])
    max_ram = int(sys.argv[3])
    transport_in, transport_out = sys.stdin, sys.stdout
    def send(value):
        transport_out.write(json.dumps(value, separators=(",", ":")) + "\n")
        transport_out.flush()
    resource.setrlimit(resource.RLIMIT_AS, (max_ram * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    lock_syscalls()
    send({"op": "ready"})
    if json.loads(transport_in.readline()) != {"go": True}:
        return
    blocked = [None]
    def audit(event, args):
        # Classification only; kernel seccomp remains if this hook is bypassed.
        if event.startswith("socket."):
            blocked[0] = "socket_attempt"
            raise PermissionError("socket_attempt")
    sys.addaudithook(audit)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(bundle))
    os.chdir(private)
    class API:
        schema = os.environ["RT_SCHEMA"]
        judge_model_path = str(bundle / "judge_model")
        @staticmethod
        def request(value):
            send(value)
            reply = json.loads(transport_in.readline())
            if "error" in reply:
                raise RuntimeError(reply["error"])
            return reply.get("value")
        def complete(self, messages):
            return self.request({"op": "complete", "messages": messages})
        def emit(self, verdict):
            self.request({"op": "emit", "verdict": verdict})
    class Sink:
        def write(self, text):
            return len(text)
        def flush(self):
            pass
    sys.stdout = sys.stderr = Sink()
    try:
        importlib.import_module("judge.main").run(API())
        send({"op": "done", "error": blocked[0]})
    except MemoryError:
        send({"op": "done", "error": "oom"})
    except BaseException:
        send({"op": "done", "error": blocked[0] or "runtime_exception"})


if __name__ == "__main__":
    main()
