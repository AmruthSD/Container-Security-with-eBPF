from ctypes import *
import os
import struct
import signal
import sys
import ctypes

# ---------------------------
# Load libbpf
# ---------------------------
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

libbpf.bpf_map_lookup_elem.argtypes = [c_int, c_void_p, c_void_p]
libbpf.bpf_map_lookup_elem.restype = c_int

libbpf.bpf_map_get_next_key.argtypes = [c_int, c_void_p, c_void_p]
libbpf.bpf_map_get_next_key.restype = c_int

libbpf.bpf_link__destroy.argtypes = [c_void_p]

# ⭐ CRITICAL ADDITION
libbpf.bpf_map__set_pin_path.argtypes = [c_void_p, c_char_p]
libbpf.bpf_map__set_pin_path.restype = c_int

# ---------------------------
# Config
# ---------------------------
BPF_OBJ_FILE = b"capset_block.o"
PROGRAM_NAME = b"block_capset"

CGROUP_MAP = b"cgroup_filter"

PINNED_CGROUP_PATH = b"/sys/fs/bpf/cgroup_filter"

# ---------------------------
# Open BPF object
# ---------------------------
obj = libbpf.bpf_object__open_file(BPF_OBJ_FILE, None)
if not obj:
    raise RuntimeError("Failed to open BPF object")

# ---------------------------
# 🔥 Bind maps BEFORE load
# ---------------------------
def reuse_map(obj, map_name, pinned_path):
    map_ptr = libbpf.bpf_object__find_map_by_name(obj, map_name)
    if not map_ptr:
        raise RuntimeError(f"Map {map_name.decode()} not found")

    res = libbpf.bpf_map__set_pin_path(map_ptr, pinned_path)
    if res != 0:
        raise RuntimeError(f"Failed to bind {map_name.decode()} to pinned path")

reuse_map(obj, CGROUP_MAP, PINNED_CGROUP_PATH)

# ---------------------------
# Load BPF object
# ---------------------------
if libbpf.bpf_object__load(obj) != 0:
    raise RuntimeError("Failed to load BPF object")

# ---------------------------
# Attach program
# ---------------------------
prog = libbpf.bpf_object__find_program_by_name(obj, PROGRAM_NAME)
if not prog:
    raise RuntimeError("Program not found")

link = libbpf.bpf_program__attach_lsm(prog)
if not link:
    raise RuntimeError("Attach failed")

print("[+] LSM program attached")

# ---------------------------
# Get map FD (now guaranteed same map)
# ---------------------------
def get_map_fd(pinned_path):
    fd = libbpf.bpf_obj_get(pinned_path)
    if fd < 0:
        raise RuntimeError(f"Failed to open pinned map {pinned_path.decode()}")
    return fd

cgroup_fd = get_map_fd(PINNED_CGROUP_PATH)

# ---------------------------
# Dump cgroup map (debug)
# ---------------------------
def dump_map(fd: int):
    key = ctypes.create_string_buffer(8)
    next_key = ctypes.create_string_buffer(8)
    value = ctypes.create_string_buffer(1)

    ret = libbpf.bpf_map_get_next_key(fd, None, next_key)

    while ret == 0:
        if libbpf.bpf_map_lookup_elem(fd, next_key, value) == 0:
            k = struct.unpack("<Q", next_key.raw)[0]
            v = struct.unpack("<B", value.raw)[0]
            print(f"[MAP] key={k}, value={v}")

        key.raw = next_key.raw
        ret = libbpf.bpf_map_get_next_key(fd, key, next_key)

dump_map(cgroup_fd)

# ---------------------------
# Cleanup handler
# ---------------------------
def cleanup(sig, frame):
    print("\n[+] Detaching...")
    if link:
        libbpf.bpf_link__destroy(link)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

print("[+] Running... Press Ctrl+C to stop.")
signal.pause()
