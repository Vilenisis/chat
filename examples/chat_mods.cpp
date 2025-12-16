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

bool equals_ignore_case(const char* lhs, const char* rhs) {
    if (!lhs || !rhs) return false;
    while (*lhs && *rhs) {
        if (std::tolower(static_cast<unsigned char>(*lhs)) !=
            std::tolower(static_cast<unsigned char>(*rhs))) {
            return false;
        }
        ++lhs;
        ++rhs;
    }
    return *lhs == '\0' && *rhs == '\0';
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

    struct ColorRule {
        const char* type;
        const char* code;
    };

    // Можно расширить этот список своими правилами
    static constexpr ColorRule rules[] = {
        {"ORANGE", "\033[38;5;214m"}, // обычные сообщения
        {"MD", "\033[38;5;196m"},     // личные сообщения
        {"DM", "\033[38;5;196m"},     // альтернативный префикс лички
        {"SYS", "\033[38;5;111m"},    // системные уведомления
    };

    for (const auto& rule : rules) {
        if (equals_ignore_case(message_type, rule.type)) {
            std::snprintf(
                color_code_buffer,
                static_cast<std::size_t>(buffer_size),
                "%s",
                rule.code);
            break;
        }
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
    } else {
        // Если префикса нет (например, ЛС через @user <text>), используем ORANGE по умолчанию.
        type = "ORANGE";
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

