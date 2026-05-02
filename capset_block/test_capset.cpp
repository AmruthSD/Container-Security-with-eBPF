#include <iostream>
#include <sys/capability.h>
#include <unistd.h>
#include <cstring>
#include <errno.h>

int main() {
    sleep(5); // allow loader to attach

    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];

    memset(&hdr, 0, sizeof(hdr));
    memset(&data, 0, sizeof(data));

    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;

    data[0].effective = 0;
    data[0].permitted = 0;
    data[0].inheritable = 0;

    int ret = capset(&hdr, data);

    if (ret == 0) {
        std::cout << "[ALLOWED] capset succeeded\n";
    } else {
        std::cout << "[BLOCKED] capset failed (errno="
                  << errno << " " << strerror(errno) << ")\n";
    }

    return 0;
}
