#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>

static void attempt_kill(pid_t pid)
{
    std::cout << "[*] Attempting kill(SIGTERM) against PID " << pid << "\n";

    if (kill(pid, SIGTERM) == 0) {
        std::cout << "[ALLOWED] kill succeeded\n";
        return;
    }

    std::cout << "[BLOCKED] kill failed (errno="
              << errno << " " << strerror(errno) << ")\n";
}

int main(int argc, char **argv)
{
    sleep(5); // allow the loader and control plane to attach/track the container

    if (argc > 1) {
        attempt_kill(static_cast<pid_t>(atoi(argv[1])));
        return 0;
    }

    pid_t child = fork();
    if (child < 0) {
        std::cerr << "fork failed: " << strerror(errno) << "\n";
        return 1;
    }

    if (child == 0) {
        pause();
        return 0;
    }

    std::cout << "[*] No external PID supplied; testing same-container child first\n";
    attempt_kill(child);
    waitpid(child, nullptr, 0);

    std::cout << "[*] Pass a host/container PID as argv[1] to test cross-cgroup blocking\n";
    return 0;
}
