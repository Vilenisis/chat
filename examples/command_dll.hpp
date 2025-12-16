#pragma once

#if defined(_WIN32)
  #define DLL_EXPORT extern "C" __declspec(dllexport)
#else
  #define DLL_EXPORT extern "C" __attribute__((visibility("default")))
#endif

// Выполняет shell-команду и передает stdout+код возврата в callback.
DLL_EXPORT void execute_command(const char* cmd, void(*callback)(const char*));
