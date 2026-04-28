#include <iostream>
#include <unistd.h>

int main() {
  std::cout << "[test2] If you see this, blocking FAILED. PID: " << getpid()
            << std::endl;
  return 0;
}