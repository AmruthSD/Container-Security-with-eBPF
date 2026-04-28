#include <bits/stdc++.h>
#include <unistd.h>

int main(){
    std::cout << "Hello from container" << std::endl;
    std::cout << "PID: " << getpid() << std::endl;

    std::cout << "Sleeping for 5 seconds..." << std::endl;
    sleep(5);

    std::ifstream file1("/unprotected.txt");
    if (!file1) {
        std::cerr << "Failed to open /etc/shadow (permission denied?)" << std::endl;
        return 1;
    }

    std::string line1;
    while (std::getline(file1, line1)) {
        std::cout << line1 << std::endl;
    }

    std::ifstream file("/protected.txt");
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