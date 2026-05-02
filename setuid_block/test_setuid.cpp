#include <iostream>
#include <unistd.h>
#include <errno.h>
#include <cstring>

int main() {
    sleep(5); // allow loader to attach

    uid_t target = 1000;

    int ret = setuid(target);

    if (ret == 0) {
        std::cout << "[ALLOWED] setuid succeeded\n";
    } else {
        std::cout << "[BLOCKED] setuid failed (errno="
                  << errno << " " << strerror(errno) << ")\n";
    }

    return 0;
}
