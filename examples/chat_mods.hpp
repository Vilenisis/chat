#pragma once

#if defined(_WIN32)
  #define CHAT_DLL_EXPORT extern "C" __declspec(dllexport)
#else
  #define CHAT_DLL_EXPORT extern "C" __attribute__((visibility("default"), used))
#endif

// Простейший пример DLL, которая добавляет цвет сообщениям.
// Ожидается формат текста: `TYPE: Текст сообщения` (например, ORANGE, MD, DM, SYS).
// Сервер всегда вызывает только chat_transform — остальные функции необязательные
// вспомогательные (оставлены для примера расширений).
CHAT_DLL_EXPORT void apply_chat_modifications(const char* message_type,
                                              char* color_code_buffer,
                                              int buffer_size);

CHAT_DLL_EXPORT bool should_color_message(const char* username);

// Основная точка входа для сервера: модифицирует текст, добавляя ANSI-код цвета.
// Возвращает указатель на внутреннюю строку (не освобождайте его самостоятельно).
CHAT_DLL_EXPORT const char* chat_transform(const char* username, const char* text);

