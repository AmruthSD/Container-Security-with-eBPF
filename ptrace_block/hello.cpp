#include <cstring>
#include <errno.h>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {

  pid_t target = 1;

  std::cout << "[*] Attempting to ptrace attach to PID: " << target << "\n";

  if (ptrace(PTRACE_ATTACH, target, nullptr, nullptr) == -1) {
    std::cerr << "[!] ptrace failed: " << strerror(errno) << "\n";

    if (errno == EPERM) {
      std::cerr << "[+] Likely blocked by LSM/eBPF 🎯\n";
    }

    return 1;
  }

  std::cout << "[+] Successfully attached (unexpected if policy is working)\n";

  waitpid(target, nullptr, 0);

  ptrace(PTRACE_DETACH, target, nullptr, nullptr);

  return 0;
}