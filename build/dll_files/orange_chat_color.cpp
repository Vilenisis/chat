#include <string>

extern "C" {
__declspec(dllexport) void apply_chat_modifications(std::string& message_type, std::string& color_code) {
    if (message_type == "ORANGE") {
        color_code = "\033[38;5;214m"; // Оранжевый цвет
    }
}

__declspec(dllexport) bool should_color_message(const std::string& username) {
    // Все сообщения окрашиваем в оранжевый
    return true;
}
}