#include "chat_lib.hpp"

#include <cstdint>
#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: server <port>\n";
        return 1;
    }
    std::uint16_t port = static_cast<std::uint16_t>(std::stoi(argv[1]));
    try {
        chat::run_server(port);
    } catch (const std::exception& e) {
        std::cerr << "server error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
