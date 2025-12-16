#include "command_dll.hpp"

#include <array>
#include <cstdio>
#include <string>

#if defined(_WIN32)
  #define PIPE_OPEN _popen
  #define PIPE_CLOSE _pclose
#else
  #include <sys/wait.h>
  #define PIPE_OPEN popen
  #define PIPE_CLOSE pclose
#endif

namespace {
std::string run_command(const char* cmd, int& exit_code) {
    std::string output;
    FILE* pipe = PIPE_OPEN(cmd, "r");
    if (!pipe) {
        exit_code = -1;
        return "Не удалось запустить команду";
    }

    std::array<char, 256> buf{};
    while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        output.append(buf.data());
    }

    exit_code = PIPE_CLOSE(pipe);
#if !defined(_WIN32)
    if (exit_code >= 0 && WIFEXITED(exit_code)) {
        exit_code = WEXITSTATUS(exit_code);
    }
#endif
    return output;
}
}  // namespace

DLL_EXPORT void execute_command(const char* cmd, void(*callback)(const char*)) {
    if (!cmd || !callback) return;

    int exit_code = 0;
    std::string stdout_data = run_command(cmd, exit_code);

    std::string message = "Command: " + std::string(cmd) +
        "\nExit code: " + std::to_string(exit_code) +
        "\nOutput:\n" + stdout_data;

    callback(message.c_str());
}
