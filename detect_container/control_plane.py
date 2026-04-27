import os
import sys
import json
import struct
import signal
import logging
import threading
import subprocess
import time
import errno
import ctypes
from ctypes import CDLL, c_int, c_char_p, c_void_p, c_ulonglong
from pathlib import Path
from queue import Queue, Empty
from typing import Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ebpf-plane")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MAP_PATH         = "/sys/fs/bpf/cgroup_filter"   # pinned map path
CGROUPFS_ROOT    = "/sys/fs/cgroup"               # cgroup v2 mountpoint
DOCKER_CGROUP_PREFIX = "system.slice/docker-"     # adjust for your cgroup driver
                                                  # (cgroupfs driver: "docker/")
MAP_UPDATE_ANY   = 0                              # BPF_ANY flag

# Map definition — must match your BPF program's map definition exactly
MAP_TYPE_HASH    = 1                              # BPF_MAP_TYPE_HASH
MAP_KEY_SIZE     = 8                              # sizeof(u64)  — cgid
MAP_VALUE_SIZE   = 1                              # sizeof(u8)   — present flag
MAP_MAX_ENTRIES  = 1024
MAP_NAME         = b"cgroup_filter"               # up to 16 bytes, cosmetic

# BPF syscall constants
NR_BPF           = 321                            # x86-64; arm64=280, adjust if needed
BPF_MAP_CREATE   = 0
BPF_OBJ_PIN      = 6
BPF_OBJ_GET      = 7

# ---------------------------------------------------------------------------
# BPF syscall wrappers  (no libbpf needed for create/pin)
# ---------------------------------------------------------------------------

class _BpfAttrCreate(ctypes.Structure):
    """union bpf_attr for BPF_MAP_CREATE."""
    _fields_ = [
        ("map_type",     ctypes.c_uint32),
        ("key_size",     ctypes.c_uint32),
        ("value_size",   ctypes.c_uint32),
        ("max_entries",  ctypes.c_uint32),
        ("map_flags",    ctypes.c_uint32),
        ("inner_map_fd", ctypes.c_uint32),
        ("numa_node",    ctypes.c_uint32),
        ("map_name",     ctypes.c_char * 16),
    ]


class _BpfAttrObjPin(ctypes.Structure):
    """union bpf_attr for BPF_OBJ_PIN / BPF_OBJ_GET."""
    _fields_ = [
        ("pathname",   ctypes.c_uint64),
        ("bpf_fd",     ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


def _bpf_syscall(cmd: int, attr: ctypes.Structure) -> int:
    """Raw bpf(2) syscall. Returns fd >= 0 on success, raises OSError on failure."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ret  = libc.syscall(NR_BPF, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def _bpf_map_create() -> int:
    """Create a BPF_MAP_TYPE_HASH and return its fd."""
    attr = _BpfAttrCreate(
        map_type    = MAP_TYPE_HASH,
        key_size    = MAP_KEY_SIZE,
        value_size  = MAP_VALUE_SIZE,
        max_entries = MAP_MAX_ENTRIES,
        map_name    = MAP_NAME,
    )
    fd = _bpf_syscall(BPF_MAP_CREATE, attr)
    log.info("Created new BPF map fd=%d  (HASH, key=u64, val=u8, max=%d)",
             fd, MAP_MAX_ENTRIES)
    return fd


def _bpf_obj_pin(fd: int, path: str):
    """Pin a BPF fd to a bpffs path."""
    path_buf = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = _BpfAttrObjPin(
        pathname = ctypes.cast(path_buf, ctypes.c_void_p).value,
        bpf_fd   = fd,
    )
    _bpf_syscall(BPF_OBJ_PIN, attr)
    log.info("Pinned map to %s", path)


def _ensure_bpffs(path: str):
    """Ensure the parent directory exists and is a bpffs mount."""
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)

    with open("/proc/mounts") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == parent and parts[2] == "bpf":
                return  # already mounted

    ret = os.system(f"mount -t bpf bpffs {parent}")
    if ret != 0:
        raise RuntimeError(f"Failed to mount bpffs at {parent}")
    log.info("Mounted bpffs at %s", parent)

# ---------------------------------------------------------------------------
# libbpf shim
# ---------------------------------------------------------------------------

def _load_libbpf() -> CDLL:
    for name in ("libbpf.so.1", "libbpf.so.0"):
        try:
            lib = CDLL(name)
            lib.bpf_obj_get.argtypes  = [c_char_p]
            lib.bpf_obj_get.restype   = c_int
            lib.bpf_map_update_elem.argtypes = [c_int, c_void_p, c_void_p, c_ulonglong]
            lib.bpf_map_update_elem.restype  = c_int
            lib.bpf_map_delete_elem.argtypes = [c_int, c_void_p]
            lib.bpf_map_delete_elem.restype  = c_int
            log.info("Loaded %s", name)
            return lib
        except OSError:
            continue
    raise RuntimeError("libbpf.so not found — install libbpf or adjust LD_LIBRARY_PATH")


libbpf = _load_libbpf()

# ---------------------------------------------------------------------------
# eBPF map helpers
# ---------------------------------------------------------------------------

def map_ensure(path: str) -> int:
    fd = libbpf.bpf_obj_get(path.encode())
    if fd >= 0:
        log.info("Found existing pinned map at %s  fd=%d", path, fd)
        return fd

    # bpf_obj_get sets errno; ENOENT means pin file doesn't exist yet
    err = ctypes.get_errno()
    if err != errno.ENOENT:
        raise OSError(err, f"bpf_obj_get({path}) failed: {os.strerror(err)}")

    log.info("No pinned map found at %s — creating a new one...", path)
    _ensure_bpffs(path)
    fd = _bpf_map_create()
    _bpf_obj_pin(fd, path)
    return fd


def map_insert(fd: int, cgid: int) -> bool:
    key   = struct.pack("Q", cgid)          # u64 little-endian
    value = struct.pack("B", 1)             # u8 — adjust to your map value type
    ret   = libbpf.bpf_map_update_elem(fd, key, value, MAP_UPDATE_ANY)
    return ret == 0


def map_delete(fd: int, cgid: int) -> bool:
    key = struct.pack("Q", cgid)
    ret = libbpf.bpf_map_delete_elem(fd, key)
    return ret == 0

# ---------------------------------------------------------------------------
# Cgroup ID resolution
# ---------------------------------------------------------------------------

def _cgid_from_path(cgroup_path: str) -> Optional[int]:
    """
    Read the cgroup ID from the kernel via statfs(2) st_ino on the
    cgroup directory.  The inode number of a cgroup v2 directory IS
    the cgroup ID used by BPF helpers such as bpf_get_current_cgroup_id().
    """
    full = os.path.join(CGROUPFS_ROOT, cgroup_path.lstrip("/"))
    try:
        return os.stat(full).st_ino
    except FileNotFoundError:
        return None


def _container_cgroup_path(cid: str) -> Optional[str]:
    """
    Ask Docker for the full cgroup path of a container.
    Works with both cgroupfs and systemd cgroup drivers.
    """
    try:
        raw = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.HostConfig.CgroupParent}}|{{.Id}}", cid],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode().strip()
        parent, full_id = raw.split("|")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
        return None

    # Detect cgroup driver from /proc/self/cgroup
    # Under systemd driver the slice is system.slice/docker-<id>.scope
    # Under cgroupfs driver it's just docker/<id>
    if _is_systemd_driver():
        return f"system.slice/docker-{full_id}.scope"
    else:
        return f"docker/{full_id}"


_systemd_driver_cache: Optional[bool] = None

def _is_systemd_driver() -> bool:
    global _systemd_driver_cache
    if _systemd_driver_cache is not None:
        return _systemd_driver_cache
    try:
        info = json.loads(
            subprocess.check_output(["docker", "info", "--format", "{{json .CgroupDriver}}"],
                                    stderr=subprocess.DEVNULL).decode()
        )
        _systemd_driver_cache = (info == "systemd")
    except Exception:
        _systemd_driver_cache = False
    return _systemd_driver_cache


def resolve_cgid(cid: str, retries: int = 10, delay: float = 0.2) -> Optional[int]:
    """
    Resolve the cgroup ID for a container with retries.
    The cgroup directory may not exist immediately after the 'start' event.
    """
    for attempt in range(retries):
        cgroup_path = _container_cgroup_path(cid)
        if cgroup_path:
            cgid = _cgid_from_path(cgroup_path)
            if cgid is not None:
                return cgid
        if attempt < retries - 1:
            time.sleep(delay)
    log.warning("Could not resolve cgid for %s after %d attempts", cid[:12], retries)
    return None

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class ContainerMap:
    """Thread-safe container → cgid registry."""

    def __init__(self, map_fd: int):
        self._fd    = map_fd
        self._lock  = threading.Lock()
        self._store: dict[str, int] = {}   # cid → cgid

    def add(self, cid: str) -> bool:
        with self._lock:
            if cid in self._store:
                return False

        cgid = resolve_cgid(cid)
        if cgid is None:
            return False

        with self._lock:
            if cid in self._store:          # double-check after I/O
                return False
            if map_insert(self._fd, cgid):
                self._store[cid] = cgid
                log.info("+ %-20s  cgid=%d", cid[:12], cgid)
                return True
            else:
                log.error("bpf_map_update_elem failed for %s", cid[:12])
                return False

    def remove(self, cid: str) -> bool:
        with self._lock:
            cgid = self._store.pop(cid, None)
        if cgid is None:
            return False
        ok = map_delete(self._fd, cgid)
        log.info("- %-20s  cgid=%d  ok=%s", cid[:12], cgid, ok)
        return ok

    def flush(self):
        """Remove all entries — called on shutdown."""
        with self._lock:
            items = list(self._store.items())
        for cid, cgid in items:
            map_delete(self._fd, cgid)
        with self._lock:
            self._store.clear()
        log.info("Map flushed (%d entries removed)", len(items))

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def bootstrap(cmap: ContainerMap):
    log.info("Bootstrapping existing containers…")
    try:
        out = subprocess.check_output(["docker", "ps", "-q"], timeout=10).decode().split()
    except subprocess.CalledProcessError as e:
        log.error("docker ps failed: %s", e)
        return

    threads = [threading.Thread(target=cmap.add, args=(cid,), daemon=True) for cid in out]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log.info("Bootstrap complete — %d container(s) tracked", len(out))

# ---------------------------------------------------------------------------
# Docker event loop
# ---------------------------------------------------------------------------

def event_loop(cmap: ContainerMap):
    cmd  = ["docker", "events", "--format", "{{json .}}"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    log.info("Listening for Docker events (pid=%d)…", proc.pid)

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("Type") != "container":
                continue

            cid    = event.get("id", "")
            action = event.get("Action", "")

            if action == "start":
                threading.Thread(target=cmap.add,    args=(cid,), daemon=True).start()
            elif action in ("die", "destroy", "stop"):
                threading.Thread(target=cmap.remove, args=(cid,), daemon=True).start()

    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if os.geteuid() != 0:
        log.error("Must run as root (eBPF map access requires CAP_BPF / root)")
        sys.exit(1)

    map_fd = map_ensure(MAP_PATH)
    log.info("Map ready  fd=%d", map_fd)

    cmap = ContainerMap(map_fd)

    def _shutdown(sig, frame):
        log.info("Signal %d received — cleaning up…", sig)
        cmap.flush()
        os.close(map_fd)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    bootstrap(cmap)
    event_loop(cmap)   # blocks


if __name__ == "__main__":
    main()