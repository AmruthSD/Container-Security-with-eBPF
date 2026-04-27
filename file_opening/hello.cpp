#include <bits/stdc++.h>
#include <unistd.h>

int main(){
    std::cout << "Hello from container" << std::endl;
    std::cout << "PID: " << getpid() << std::endl;

    std::cout << "Sleeping for 5 seconds..." << std::endl;
    sleep(5);

    std::ifstream file("/home/amruth/Desktop/mini_project/Container-Security-with-eBPF/file_opening/protected.txt");
    if (!file) {
        std::cerr << "Failed to open /etc/shadow (permission denied?)" << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::cout << line << std::endl;
    }

    return 0;
}