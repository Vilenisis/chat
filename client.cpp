#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <atomic>
#include <string>

using boost::asio::ip::tcp;
using namespace std;

// ANSI цвета
static const char* COL_DM  = "\033[32m"; // зелёный
static const char* COL_SYS = "\033[36m"; // циан
static const char* COL_FAV = "\033[33m"; // жёлтый
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

                // Игнорируем устаревший префикс ORANGE:, если он вдруг пришёл с сервера
                if (line.rfind("ORANGE:", 0) == 0) {
                    line = line.substr(7);
                }

                // подсветка типов
                if (line.rfind("DM:", 0) == 0) {
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
