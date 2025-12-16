#include "command_dll.hpp"

#include <iostream>

namespace {
void print_callback(const char* message) {
    std::cout << message << std::endl;
}
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: command_runner \"<command>\"\n";
        std::cout << "Example: command_runner \"echo Hello\"\n";
        return 1;
    }

    execute_command(argv[1], print_callback);
    return 0;
}
