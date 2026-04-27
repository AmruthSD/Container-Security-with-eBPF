from ctypes import *
import os
import struct
import signal
import sys

libbpf = CDLL("libbpf.so.0")

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

libbpf.bpf_map_update_elem.argtypes = [c_int, c_void_p, c_void_p, c_ulonglong]
libbpf.bpf_map_update_elem.restype = c_int

libbpf.bpf_link__destroy.argtypes = [c_void_p]

# ---------------------------
# Config
# ---------------------------
BPF_OBJ_FILE = b"file_opener.o"
PROGRAM_NAME = b"block_file"
MAP_NAME = b"inode_blacklist"

# Files you want to protect
PROTECTED_PATHS = [
    "/home/amruth/Desktop/mini_project/Container-Security-with-eBPF/file_opening/protected.txt",
    "/etc/shadow",
]

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
# Get map
# ---------------------------
bpf_map = libbpf.bpf_object__find_map_by_name(obj, MAP_NAME)
if not bpf_map:
    raise RuntimeError("Map not found")

map_fd = libbpf.bpf_map__fd(bpf_map)
if map_fd < 0:
    raise RuntimeError("Invalid map FD")

# ---------------------------
# Populate map
# ---------------------------
for path in PROTECTED_PATHS:
    st = os.stat(path)

    dev = st.st_dev
    ino = st.st_ino

    print(f"[+] Adding {path} → dev={dev}, ino={ino}")

    # struct inode_key { u64 dev; u64 ino; }
    key = struct.pack("QQ", dev, ino)
    value = struct.pack("B", 1)

    res = libbpf.bpf_map_update_elem(
        map_fd,
        c_char_p(key),
        c_char_p(value),
        0
    )

    if res != 0:
        raise RuntimeError(f"Failed to insert {path}")

print("[+] Map populated successfully")

# ---------------------------
# Keep alive
# ---------------------------
def cleanup(sig, frame):
    print("\n[+] Detaching...")
    libbpf.bpf_link__destroy(link)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

print("[+] Running... Press Ctrl+C to exit")
signal.pause()