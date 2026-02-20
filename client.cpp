#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <atomic>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

using boost::asio::ip::tcp;
using namespace std;

// ANSI цвета
static const char* COL_DM  = "\033[32m"; // зелёный
static const char* COL_SYS = "\033[36m"; // циан
static const char* COL_FAV = "\033[33m"; // жёлтый
static const char* COL_RST = "\033[0m";

static int openSerialPort(const string& portPath) {
    int fd = open(portPath.c_str(), O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        perror(("open serial " + portPath).c_str());
        return -1;
    }

    termios tty{};
    if (tcgetattr(fd, &tty) != 0) {
        perror("tcgetattr");
        close(fd);
        return -1;
    }

    cfsetospeed(&tty, B115200);
    cfsetispeed(&tty, B115200);

    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;
    tty.c_iflag &= ~IGNBRK;
    tty.c_lflag = 0;
    tty.c_oflag = 0;
    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 5;

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        perror("tcsetattr");
        close(fd);
        return -1;
    }

    return fd;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        cerr << "usage: client <host> <port> [serial_port]\n";
        return 1;
    }
    string host = argv[1];
    string port = argv[2];
    string serialPort = (argc >= 4) ? argv[3] : "/dev/cu.usbmodem1101";

    try {
        boost::asio::io_context io;
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(host, port);
        tcp::socket socket(io);
        boost::asio::connect(socket, endpoints);
        cout << "Connected to " << host << ":" << port << endl;

        int serialFd = openSerialPort(serialPort);
        if (serialFd >= 0) {
            cout << "Serial connected: " << serialPort << "\n";
        } else {
            cerr << "Serial disabled (can't open " << serialPort << ")\n";
        }

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

                if (serialFd >= 0) {
                    string serialMsg = "MSG: " + line + "\n";
                    ssize_t written = write(serialFd, serialMsg.c_str(), serialMsg.size());
                    if (written < 0) {
                        perror("write serial");
                    }
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
        if (serialFd >= 0) close(serialFd);

    } catch (const exception& e) {
        cerr << "client error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
