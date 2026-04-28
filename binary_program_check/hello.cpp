#include <bits/stdc++.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
  std::cout << "Hello from container" << std::endl;
  std::cout << "PID: " << getpid() << std::endl;

  while (true) {
    std::cout << "\n[+] Trying to exec /bin/ls (should be allowed or learned)"
              << std::endl;

    pid_t pid = fork();
    if (pid == 0) {
      execl("/bin/ls", "ls", NULL);
      perror("exec /bin/ls failed");
      _exit(1);
    } else {
      waitpid(pid, nullptr, 0);
    }

    sleep(2);

    std::cout << "\n[+] Trying to exec /bin/bash (good candidate for blocking)"
              << std::endl;

    pid = fork();
    if (pid == 0) {
      execl("/bin/bash", "bash", "-c", "echo inside bash", NULL);
      perror("exec /bin/bash failed");
      _exit(1);
    } else {
      waitpid(pid, nullptr, 0);
    }

    sleep(5);
  }

  return 0;
}