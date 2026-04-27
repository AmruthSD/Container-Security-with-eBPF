from ctypes import *
import signal
import sys

libbpf = CDLL("libbpf.so.1")

# ---- libbpf function prototypes ----
libbpf.bpf_object__open_file.argtypes = [c_char_p, c_void_p]
libbpf.bpf_object__open_file.restype = c_void_p

libbpf.bpf_object__load.argtypes = [c_void_p]
libbpf.bpf_object__load.restype = c_int

libbpf.bpf_object__find_program_by_name.argtypes = [c_void_p, c_char_p]
libbpf.bpf_object__find_program_by_name.restype = c_void_p

libbpf.bpf_program__attach.argtypes = [c_void_p]
libbpf.bpf_program__attach.restype = c_void_p

libbpf.bpf_link__destroy.argtypes = [c_void_p]

# ---- open BPF object ----
obj = libbpf.bpf_object__open_file(b"check_std_write.o", None)
if not obj:
    raise RuntimeError("Failed to open BPF object")

# ---- load into kernel ----
if libbpf.bpf_object__load(obj) != 0:
    raise RuntimeError("Failed to load BPF object")

# ---- find program ----
prog = libbpf.bpf_object__find_program_by_name(obj, b"trace_write_stdout")
if not prog:
    raise RuntimeError("BPF program not found (check function name)")

# ---- attach ----
link = libbpf.bpf_program__attach(prog)
if not link:
    raise RuntimeError("Failed to attach BPF program")

print("Attached to sys_enter_write. Ctrl+C to exit.")

# ---- graceful detach ----
def cleanup(sig, frame):
    print("\nDetaching...")
    libbpf.bpf_link__destroy(link)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

signal.pause()
