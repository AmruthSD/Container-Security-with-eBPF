#include <iostream>
#include <unistd.h>

int main() {
  std::cout << "[test1] Running (allowed). PID: " << getpid() << std::endl;
  return 0;
}