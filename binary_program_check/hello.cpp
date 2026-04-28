#include <iostream>
#include <sys/wait.h>
#include <unistd.h>

void run(const char *path) {
  pid_t pid = fork();
  if (pid == 0) {
    execl(path, path, NULL);
    perror("exec failed");
    _exit(1);
  } else {
    waitpid(pid, nullptr, 0);
  }
}

int main() {
  std::cout << "[hello] PID: " << getpid() << std::endl;

  std::cout << "[hello] Running test1 (should be learned)" << std::endl;
  run("/test1");

  std::cout << "[hello] Sleeping to allow learning phase..." << std::endl;
  sleep(2); // must be > LEARN_WINDOW + GRACE in your eBPF

  std::cout << "[hello] Running test1 again (should be allowed)" << std::endl;
  run("/test1");

  std::cout << "[hello] Running test2 (should be BLOCKED)" << std::endl;
  run("/test2");

  std::cout << "[hello] Done" << std::endl;
  return 0;
}