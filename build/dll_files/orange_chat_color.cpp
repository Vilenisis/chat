// chat_mods.cpp
#include <cstring>  // strcmp, strncpy
#include <cstdio>   // snprintf (или _snprintf_s под MSVC)

// Экспортируем функции в C-стиле, чтобы имена не были заманглены
extern "C" {

__declspec(dllexport)
void apply_chat_modifications(const char* message_type,
                              char* color_code_buffer,
                              int buffer_size)
{
    if (!message_type  !color_code_buffer  buffer_size <= 0) {
        return;
    }

    // По умолчанию — пустая строка (нет цвета)
    color_code_buffer[0] = '\0';

    // Если тип сообщения ORANGE — задаём цвет
    if (std::strcmp(message_type, "ORANGE") == 0) {
        const char* orange_code = "\033[38;5;214m"; // Оранжевый цвет

        // Аккуратно копируем в буфер, с гарантией \0 в конце
        std::snprintf(color_code_buffer, buffer_size, "%s", orange_code);
    }
}

__declspec(dllexport)
bool should_color_message(const char* username)
{
    // Здесь ты можешь дальше усложнять логику:
    // например, не красить системные сообщения, ботов и т.д.
    // Сейчас — всегда true, как и было.
    (void)username; // чтобы компилятор не ругался, если не используешь

    return true;
}

} // extern "C"