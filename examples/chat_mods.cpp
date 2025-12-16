#include "chat_mods.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

namespace {
std::string trim(const std::string& value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch);
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch);
    }).base();
    if (first >= last) return {};
    return std::string(first, last);
}
}

// Экспортируем функции в C-стиле, чтобы имена не были заманглены
extern "C" {

CHAT_DLL_EXPORT
void apply_chat_modifications(const char* message_type,
                              char* color_code_buffer,
                              int buffer_size)
{
    if (!message_type || !color_code_buffer || buffer_size <= 0) {
        return;
    }

    // По умолчанию — пустая строка (нет цвета)
    color_code_buffer[0] = '\0';

    // Если тип сообщения ORANGE — задаём цвет
    if (std::strcmp(message_type, "ORANGE") == 0) {
        const char* orange_code = "\033[38;5;214m"; // Оранжевый цвет

        // Аккуратно копируем в буфер, с гарантией \0 в конце
        std::snprintf(color_code_buffer, static_cast<std::size_t>(buffer_size), "%s", orange_code);
    }
}

CHAT_DLL_EXPORT
bool should_color_message(const char* username)
{
    (void)username; // можно использовать для расширения логики
    return true;
}

CHAT_DLL_EXPORT
const char* chat_transform(const char* username, const char* text)
{
    static thread_local std::string transformed;

    if (!text) return nullptr;

    std::string message{text};
    std::string type;

    // Ожидаем формат вида "TYPE: текст". Если двоеточия нет, текст остаётся неизменным.
    auto colon_pos = message.find(':');
    if (colon_pos != std::string::npos) {
        type = trim(message.substr(0, colon_pos));
        message = trim(message.substr(colon_pos + 1));
    }

    char color_code[32] = {0};
    if (!type.empty()) {
        apply_chat_modifications(type.c_str(), color_code, static_cast<int>(sizeof(color_code)));
    }

    if (color_code[0] != '\0' && should_color_message(username)) {
        transformed.assign(color_code);
        transformed += message;
        transformed += "\033[0m"; // сброс цвета
    } else {
        transformed = message;
    }

    return transformed.c_str();
}

} // extern "C"

