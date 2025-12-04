#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <atomic>
#include <string>
#include <sstream>

#include <vector>
#include <cctype>




// Разбивка UTF-8 на "символы" (кодпоинты), чтобы не резать кириллицу по байтам
static std::vector<std::string> utf8_chars(const std::string& s) {
    std::vector<std::string> out;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t len = 1;
        if      ((c & 0x80) == 0x00) len = 1;
        else if ((c & 0xE0) == 0xC0) len = 2;
        else if ((c & 0xF0) == 0xE0) len = 3;
        else if ((c & 0xF8) == 0xF0) len = 4;
        // защитимся от кривых байтов
        if (i + len > s.size()) len = 1;
        out.emplace_back(s.substr(i, len));
        i += len;
    }
    return out;
}

static bool is_ascii_punct(char c) {
    // Хотим сохранить примыкающую пунктуацию (.,!?… и т.п.)
    const std::string p = ".,!?;:()[]{}\"'«»…";
    return p.find(c) != std::string::npos;
}

// Маскируем одно "слово": первые 2 + последние 2 символа, остальное выкидываем
static std::string transform_token(const std::string& tok) {
    // отделим ASCII-пунктуацию по краям, чтобы не искажать её
    size_t start = 0, end = tok.size();
    while (start < end && is_ascii_punct(tok[start])) start++;
    while (end > start && is_ascii_punct(tok[end - 1])) end--;

    std::string lead  = tok.substr(0, start);
    std::string core  = tok.substr(start, end - start);
    std::string trail = tok.substr(end);

    auto chars = utf8_chars(core);
    if (chars.size() <= 4) return tok; // короткие слова оставляем как есть

    std::string out = chars[0] + chars[1] + chars[chars.size() - 2] + chars.back();
    return lead + out + trail;
}

// Маскируем весь текст сообщения (разбиваем по пробелам, собираем обратно одним пробелом)
static std::string mask_message(const std::string& msg) {
    std::istringstream iss(msg);
    std::string tok;
    std::vector<std::string> parts;
    while (iss >> tok) parts.push_back(transform_token(tok));
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out.push_back(' ');
        out += parts[i];
    }
    return out;
}

using boost::asio::ip::tcp;
using namespace std;

// ANSI цвета
static const char* COL_DM  = "\033[32m"; // зелёный
static const char* COL_SYS = "\033[36m"; // циан
static const char* COL_FAV = "\033[33m"; // жёлтый
static const char* COL_ORANGE = "\033[38;5;214m"; // оранжевый
static const char* COL_RST = "\033[0m";

int main(int argc, char** argv) {
    if (argc < 3) {
        cerr << "usage: client <host> <port>\n";
        return 1;
    }
    string host = argv[1];
    string port = argv[2];

    try {
        boost::asio::io_context io;
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(host, port);
        tcp::socket socket(io);
        boost::asio::connect(socket, endpoints);
        cout << "Connected to " << host << ":" << port << endl;

        atomic<bool> running{true};

        // поток чтения из сокета
        thread reader([&](){
            boost::asio::streambuf buf;
            while (running.load()) {
                boost::system::error_code ec;
                size_t n = boost::asio::read_until(socket, buf, '\n', ec);
                if (ec) { 
                    cerr << "Disconnected: " << ec.message() << "\n"; 
                    running = false; 
                    break; 
                }
                istream is(&buf);
                string line;
                getline(is, line);
                cout << "Received: " << line << endl; // Лог полученного сообщения

                // Если это DM/MSG/FAV — замаскируем только часть после последнего ": "
                auto needs_mask = (line.rfind("DM:", 0) == 0) || (line.rfind("MSG:", 0) == 0) || (line.rfind("FAV:", 0) == 0);
                if (needs_mask) {
                    size_t sep = line.rfind(": ");
                    if (sep != std::string::npos && sep + 2 < line.size()) {
                        std::string header = line.substr(0, sep + 2);  // включает ": "
                        std::string body   = line.substr(sep + 2);
                        line = header + mask_message(body);
                    }
                }

                // подсветка типов с поддержкой оранжевого цвета
                if (line.rfind("ORANGE:", 0) == 0) {
                    // Убираем префикс ORANGE: для отображения
                    std::string display_line = line.substr(7);
                    cout << COL_ORANGE << display_line << COL_RST << "\n";
                } else if (line.rfind("DM:", 0) == 0) {
                    cout << COL_DM << line << COL_RST << "\n";
                } else if (line.rfind("SYS:", 0) == 0) {
                    cout << COL_SYS << line << COL_RST << "\n";
                } else if (line.rfind("FAV:", 0) == 0) {
                    cout << COL_FAV << line << COL_RST << "\n";
                } else {
                    cout << line << "\n";
                }
            }
        });


        // основной поток: читаем stdin и шлём на сервер
        std::string line;
        while (running.load() && std::getline(cin, line)) {
            // локальная команда выхода (не уходит на сервер)
            if (line == "#exit" || line == "#quit" || line == "/exit") {
                try {
                    socket.shutdown(tcp::socket::shutdown_both);
                } catch (...) {}
                boost::system::error_code ec;
                socket.close(ec);
                running = false;
                break;
            }
            line.push_back('\n');
            cout << "Sending: " << line << endl; // Лог отправляемого сообщения
            boost::asio::write(socket, boost::asio::buffer(line));
        }
        running = false;
        if (reader.joinable()) reader.join();

    } catch (const exception& e) {
        cerr << "client error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
