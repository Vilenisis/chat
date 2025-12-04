#include <boost/asio.hpp>
#include <iostream>
#include <string>

using boost::asio::ip::tcp;

int main() {
    try {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8081));  // ← изменили на 8081
        
        std::cout << "🚀 Working Server запущен на порту 8081" << std::endl;
        std::cout << "Ожидание подключений..." << std::endl;
        
        while (true) {
            tcp::socket socket(io_context);
            acceptor.accept(socket);
            
            std::cout << "✅ Клиент подключен!" << std::endl;
            
            // Отправляем приветствие
            std::string welcome = "SYS: Добро пожаловать в чат! Введите #me <имя>\n";
            boost::asio::write(socket, boost::asio::buffer(welcome));
            
            // Читаем сообщения от клиента
            boost::asio::streambuf buffer;
            while (true) {
                boost::system::error_code ec;
                size_t n = boost::asio::read_until(socket, buffer, '\n', ec);
                
                if (ec) {
                    std::cout << "❌ Клиент отключился" << std::endl;
                    break;
                }
                
                std::istream is(&buffer);
                std::string line;
                std::getline(is, line);
                
                std::cout << "📨 Получено: " << line << std::endl;
                
                // Отправляем эхо-ответ
                std::string response = "ECHO: " + line + "\n";
                boost::asio::write(socket, boost::asio::buffer(response));
                
                // Если клиент отправил #me, подтверждаем
                if (line.rfind("#me", 0) == 0) {
                    std::string name_msg = "SYS: Имя установлено!\n";
                    boost::asio::write(socket, boost::asio::buffer(name_msg));
                }
            }
        }
        
    } catch (std::exception& e) {
        std::cerr << "💥 Ошибка: " << e.what() << std::endl;
    }
    return 0;
}