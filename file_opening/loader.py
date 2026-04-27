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
BPF_OBJ_FILE = b"file_opener.o"
PROGRAM_NAME = b"block_file"

# Map Names (Must match C code)
INODE_MAP    = b"inode_blacklist"
PREFIX_MAP   = b"prefix_blacklist"
CGROUP_MAP   = b"cgroup_filter"

# Pinned Paths (If applicable)
PINNED_INODE_PATH  = b"/sys/fs/bpf/inode_blacklist"
PINNED_PREFIX_PATH = b"/sys/fs/bpf/prefix_blacklist"
PINNED_CGROUP_PATH = b"/sys/fs/bpf/cgroup_filter"

# Data to Block
PROTECTED_FILES = ["/etc/shadow"]
PREFIX_PATHS    = ["/root/"]
CGROUP_IDS      = [1, 12345] # Example Cgroup IDs to filter
PREFIX_LEN      = 128

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

inode_fd  = get_map_fd(PINNED_INODE_PATH, INODE_MAP)
prefix_fd = get_map_fd(PINNED_PREFIX_PATH, PREFIX_MAP)
cgroup_fd = get_map_fd(PINNED_CGROUP_PATH, CGROUP_MAP)

if any(fd < 0 for fd in [inode_fd, prefix_fd, cgroup_fd]):
    raise RuntimeError("Failed to obtain map file descriptors")

# ---------------------------
# Populate Inode Map
# ---------------------------
for path in PROTECTED_FILES:
    try:
        st = os.stat(path)
        key = struct.pack("QQ", st.st_dev, st.st_ino)
        value = struct.pack("B", 1)
        libbpf.bpf_map_update_elem(inode_fd, key, value, 0)
        print(f"[+] Inode rule: {path}")
    except FileNotFoundError:
        print(f"[!] File not found: {path}")

# ---------------------------
# Populate Prefix Map
# ---------------------------
for i, path in enumerate(PREFIX_PATHS):
    key = struct.pack("I", i)
    buf = path.encode()[:PREFIX_LEN - 1].ljust(PREFIX_LEN, b"\x00")
    libbpf.bpf_map_update_elem(prefix_fd, key, buf, 0)
    print(f"[+] Prefix rule: {path}")

# ---------------------------
# Populate Cgroup Filter Map
# ---------------------------
for cgid in CGROUP_IDS:
    # Key is __u64 (Q), Value is __u8 (B)
    key = struct.pack("Q", cgid)
    value = struct.pack("B", 1)
    res = libbpf.bpf_map_update_elem(cgroup_fd, key, value, 0)
    if res == 0:
        print(f"[+] Cgroup filter added: ID {cgid}")
    else:
        print(f"[!] Failed to add cgroup ID {cgid}")

print("[+] All maps populated successfully")

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