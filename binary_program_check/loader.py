from ctypes import *
import os
import struct
import signal
import sys

# Load libbpf
libbpf = CDLL("libbpf.so.1")

# ---------------------------
# Function prototypes
# ---------------------------
libbpf.bpf_object__open_file.argtypes = [c_char_p, c_void_p]
libbpf.bpf_object__open_file.restype = c_void_p

libbpf.bpf_object__load.argtypes = [c_void_p]
libbpf.bpf_object__load.restype = c_int

libbpf.bpf_object__find_program_by_name.argtypes = [c_void_p, c_char_p]
libbpf.bpf_object__find_program_by_name.restype = c_void_p

libbpf.bpf_program__attach.argtypes = [c_void_p]
libbpf.bpf_program__attach.restype = c_void_p

libbpf.bpf_object__find_map_by_name.argtypes = [c_void_p, c_char_p]
libbpf.bpf_object__find_map_by_name.restype = c_void_p

libbpf.bpf_map__fd.argtypes = [c_void_p]
libbpf.bpf_map__fd.restype = c_int

libbpf.bpf_obj_get.argtypes = [c_char_p]
libbpf.bpf_obj_get.restype = c_int

libbpf.bpf_map_update_elem.argtypes = [c_int, c_void_p, c_void_p, c_ulonglong]
libbpf.bpf_map_update_elem.restype = c_int

libbpf.bpf_link__destroy.argtypes = [c_void_p]

# ---------------------------
# Config
# ---------------------------
BPF_OBJ_FILE = b"binary_checker.o"
PROGRAM_NAME = b"exec_control"

CGROUP_MAP   = b"cgroup_filter"

PINNED_CGROUP_PATH = b"/sys/fs/bpf/cgroup_filter"

# ---------------------------
# Open + load BPF
# ---------------------------
obj = libbpf.bpf_object__open_file(BPF_OBJ_FILE, None)
if not obj:
    raise RuntimeError("Failed to open BPF object")

if libbpf.bpf_object__load(obj) != 0:
    raise RuntimeError("Failed to load BPF object")

# ---------------------------
# Attach program
# ---------------------------
prog = libbpf.bpf_object__find_program_by_name(obj, PROGRAM_NAME)
if not prog:
    raise RuntimeError("Program not found")

link = libbpf.bpf_program__attach(prog)
if not link:
    raise RuntimeError("Attach failed")
print("[+] LSM program attached")

# ---------------------------
# Helper to get FD (Pinned or Object)
# ---------------------------
def get_map_fd(pinned_path, map_name):
    fd = libbpf.bpf_obj_get(pinned_path)
    if fd < 0:
        print(f"[-] Pinned {map_name.decode()} not found, using object map...")
        map_ptr = libbpf.bpf_object__find_map_by_name(obj, map_name)
        fd = libbpf.bpf_map__fd(map_ptr)
    return fd

cgroup_fd = get_map_fd(PINNED_CGROUP_PATH, CGROUP_MAP)

# ---------------------------
# Keep alive
# ---------------------------
def cleanup(sig, frame):
    print("\n[+] Detaching and exiting...")
    if link:
        libbpf.bpf_link__destroy(link)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

print("[+] Running... Press Ctrl+C to stop.")
signal.pause()