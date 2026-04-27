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

INODE_MAP = b"inode_blacklist"
PREFIX_MAP = b"prefix_blacklist"

# Exact files (inode-based)
PROTECTED_FILES = [
    "/home/amruth/Desktop/mini_project/Container-Security-with-eBPF/file_opening/protected.txt",
    "/etc/shadow",
]

# Prefix rules
PREFIX_PATHS = [
    "/etc/",
    "/root/",
]

PREFIX_LEN = 128

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

link = libbpf.bpf_program__attach_lsm(prog)
if not link:
    raise RuntimeError("Attach failed")

print("[+] LSM program attached")

# ---------------------------
# Get maps
# ---------------------------
inode_map = libbpf.bpf_object__find_map_by_name(obj, INODE_MAP)
prefix_map = libbpf.bpf_object__find_map_by_name(obj, PREFIX_MAP)

if not inode_map or not prefix_map:
    raise RuntimeError("Failed to find maps")

inode_fd = libbpf.bpf_map__fd(inode_map)
prefix_fd = libbpf.bpf_map__fd(prefix_map)

# ---------------------------
# Populate inode map
# ---------------------------
for path in PROTECTED_FILES:
    st = os.stat(path)

    dev = st.st_dev
    ino = st.st_ino

    print(f"[+] Inode rule: {path} → dev={dev}, ino={ino}")

    key = struct.pack("QQ", dev, ino)
    value = struct.pack("B", 1)

    res = libbpf.bpf_map_update_elem(
        inode_fd,
        c_char_p(key),
        c_char_p(value),
        0
    )

    if res != 0:
        raise RuntimeError(f"Failed to insert inode rule: {path}")

# ---------------------------
# Populate prefix map
# ---------------------------
for i, path in enumerate(PREFIX_PATHS):
    print(f"[+] Prefix rule[{i}]: {path}")

    key = struct.pack("I", i)

    buf = path.encode()[:PREFIX_LEN - 1]
    buf = buf + b"\x00" * (PREFIX_LEN - len(buf))

    res = libbpf.bpf_map_update_elem(
        prefix_fd,
        c_char_p(key),
        c_char_p(buf),
        0
    )

    if res != 0:
        raise RuntimeError(f"Failed to insert prefix rule: {path}")

print("[+] All maps populated successfully")

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