#include <cstring>
#include <errno.h>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>

void attempt_ptrace(pid_t target) {
    std::cout << "\n[*] Attempting to ptrace attach to PID: " << target << "\n";

    if (ptrace(PTRACE_ATTACH, target, nullptr, nullptr)!=0) {
        std::cerr << "[!] ptrace failed: " << strerror(errno) << "\n";

        if (errno == EPERM) {
            std::cerr << "[+] Blocked (LSM / Yama / capability)\n";
        }
        return;
    }

    std::cout << "[+] Successfully attached to " << target << "\n";

    waitpid(target, nullptr, 0);
    ptrace(PTRACE_DETACH, target, nullptr, nullptr);

    std::cout << "[+] Detached from " << target << "\n";
}

int main(int argc, char** argv) {
    // ---------- First test: fork + child ----------
    pid_t pid = fork();

    if (pid == 0) {
        std::cout << "[child] PID: " << getpid() << " sleeping...\n";
        sleep(100);
        return 0;
    }

    sleep(1);  // ensure child is running

    std::cout << "[parent] First test (child attach)\n";
    attempt_ptrace(pid);

    // ---------- Second test: external PID ----------
    if (argc > 1) {
        pid_t target = atoi(argv[1]);

        std::cout << "\n[parent] Second test (external PID)\n";
        attempt_ptrace(target);
    } else {
        std::cout << "\n[!] No external PID provided, skipping second test\n";
        std::cout << "Usage: " << argv[0] << " <pid>\n";
    }

    return 0;
}