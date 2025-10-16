cmake_minimum_required(VERSION 3.16)
project(chat_cpp_asio LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ИСПОЛЬЗУЕМ CONFIG-режим (новый Boost), без компонентов:
find_package(Boost CONFIG REQUIRED)
find_package(Threads REQUIRED)

add_executable(server server.cpp)
add_executable(client client.cpp)

# Новый Boost даёт импортируемую цель Boost::headers (только заголовки Asio)
if (TARGET Boost::headers)
  target_link_libraries(server PRIVATE Boost::headers Threads::Threads)
  target_link_libraries(client PRIVATE Boost::headers Threads::Threads)
else()
  # На случай старых сборок Boost — подстрахуемся
  target_include_directories(server PRIVATE ${Boost_INCLUDE_DIRS})
  target_include_directories(client PRIVATE ${Boost_INCLUDE_DIRS})
  target_link_libraries(server PRIVATE Threads::Threads)
  target_link_libraries(client PRIVATE Threads::Threads)
endif()

# Для macOS rpath
set_target_properties(server client PROPERTIES
  BUILD_WITH_INSTALL_RPATH TRUE
  INSTALL_RPATH_USE_LINK_PATH TRUE
)
add_executable(server_web server_web.cpp)
target_link_libraries(server_web PRIVATE Boost::headers Threads::Threads)
set_target_properties(server_web PROPERTIES
  BUILD_WITH_INSTALL_RPATH TRUE
  INSTALL_RPATH_USE_LINK_PATH TRUE
)