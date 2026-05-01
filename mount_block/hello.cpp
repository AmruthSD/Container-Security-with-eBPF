#include <cstring>
#include <errno.h>
#include <iostream>
#include <string>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace std;

struct Test {
  string name;
  int (*fn)();
};

void ensure_dir(const char *path) {
  string cmd = string("mkdir -p ") + path;
  system(cmd.c_str());
}

// -----------------------------

int test_proc_mount() {
  ensure_dir("/tmp/mnt_proc");
  return mount("proc", "/tmp/mnt_proc", "proc", 0, nullptr);
}

int test_sysfs_mount() {
  ensure_dir("/tmp/mnt_sys");
  return mount("sysfs", "/tmp/mnt_sys", "sysfs", 0, nullptr);
}

int test_tmpfs_unsafe() {
  ensure_dir("/tmp/mnt_tmpfs");
  return mount("tmpfs", "/tmp/mnt_tmpfs", "tmpfs", 0, nullptr);
}

int test_tmpfs_safe() {
  ensure_dir("/tmp/mnt_tmpfs_safe");
  return mount("tmpfs", "/tmp/mnt_tmpfs_safe", "tmpfs",
               MS_NOEXEC | MS_NOSUID | MS_NODEV, nullptr);
}

int test_dev_mount() {
  ensure_dir("/tmp/mnt_dev");
  ensure_dir("/tmp/mnt_dev/lost+found");
  return mount("/dev", "/tmp/mnt_dev", nullptr, MS_BIND, nullptr);
}

int test_remount_suid() {
  ensure_dir("/tmp/mnt_remount");
  mount("tmpfs", "/tmp/mnt_remount", "tmpfs",
        MS_NOEXEC | MS_NOSUID | MS_NODEV, nullptr);

  return mount(nullptr, "/tmp/mnt_remount", nullptr,
               MS_REMOUNT, nullptr);
}

int test_bind_root() {
  ensure_dir("/tmp/mnt_bind");
  return mount("/", "/tmp/mnt_bind", nullptr, MS_BIND, nullptr);
}

// -----------------------------

int main() {
  sleep(5);
  vector<Test> tests = {
      {"Mount proc", test_proc_mount},
      {"Mount sysfs", test_sysfs_mount},
      {"Tmpfs without safety flags", test_tmpfs_unsafe},
      {"Tmpfs with safe flags", test_tmpfs_safe},
      {"Bind mount /dev", test_dev_mount},
      {"Remount", test_remount_suid},
      {"Bind mount /", test_bind_root},
  };

  cout << "==== Mount Security Tests ====\n";

  for (auto &t : tests) {
    errno = 0;
    int ret = t.fn();

    if (ret == 0) {
      cout << "[ALLOWED] " << t.name << "\n";
    } else {
      cout << "[BLOCKED] " << t.name << " (errno=" << errno << " "
           << strerror(errno) << ")\n";
    }
  }

  return 0;
}