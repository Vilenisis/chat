# DLL для выполнения команд

Готовый пример экспортируемой функции `execute_command` (см. `command_dll.hpp/.cpp`) и консольного клиента `command_runner`, который демонстрирует вызов DLL и печатает результат callback'а.

## Как собрать
```bash
cmake -S . -B build
cmake --build build --target command_runner
```

## Как запустить команду через DLL
```bash
./build/command_runner "echo Hello from DLL"
```

На Windows можно передать любую команду PowerShell или `cmd.exe`:
```powershell
command_runner "dir"
# или
command_runner "powershell -Command Get-Process | Select-Object -First 3"
```

Функция вернёт stdout и код выхода команды, передав их в callback.
