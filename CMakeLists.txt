cmake_minimum_required(VERSION 3.16)
project(chat_cpp_asio LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Пробуем найти Boost в config-режиме (новые поставки, например vcpkg/homebrew).
find_package(Boost CONFIG QUIET COMPONENTS system)
if(NOT Boost_FOUND)
  # На macOS через Homebrew чаще доступен модульный find_package без CONFIG.
  find_package(Boost REQUIRED COMPONENTS system)
endif()
find_package(Threads REQUIRED)

add_library(chat_core SHARED chat_lib.cpp)
set_target_properties(chat_core PROPERTIES
  WINDOWS_EXPORT_ALL_SYMBOLS TRUE
)

add_executable(server server.cpp)
add_executable(client client.cpp)
add_executable(server_web server_web.cpp)

set(_boost_header_target "")
if (TARGET Boost::headers)
  set(_boost_header_target Boost::headers)
elseif (TARGET Boost::boost)
  set(_boost_header_target Boost::boost)
endif()

if (_boost_header_target)
  target_link_libraries(chat_core PUBLIC ${_boost_header_target} Threads::Threads)
  target_link_libraries(client PRIVATE ${_boost_header_target} Threads::Threads)
  target_link_libraries(server_web PRIVATE ${_boost_header_target} Threads::Threads Boost::system)
else()
  # На случай очень старых сборок Boost — подключим include-пути вручную
  target_link_libraries(chat_core PUBLIC Boost::headers Threads::Threads)
  target_link_libraries(client PRIVATE Boost::headers Threads::Threads)
  target_link_libraries(server_web PRIVATE Boost::headers Threads::Threads Boost::system)
endif()

target_link_libraries(server PRIVATE chat_core)

# Для macOS rpath
set_target_properties(server client PROPERTIES
  BUILD_WITH_INSTALL_RPATH TRUE
  INSTALL_RPATH_USE_LINK_PATH TRUE
)
set_target_properties(server_web PROPERTIES
  BUILD_WITH_INSTALL_RPATH TRUE
  INSTALL_RPATH_USE_LINK_PATH TRUE
)