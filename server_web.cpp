#include <boost/asio.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/websocket.hpp>
#include <algorithm>
#include <atomic>
#include <csignal>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace beast = boost::beast;
namespace http  = beast::http;
namespace websocket = beast::websocket;
using tcp = boost::asio::ip::tcp;
using namespace std;

// Встроенная страница админ-панели
static const char* ADMIN_HTML = R"HTML(<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Chat DLL Admin</title>
<style>
 body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin:0; background:#030712; color:#e5e7eb; }
 header { padding:16px; background:#0f172a; border-bottom:1px solid #1f2937; font-size:20px; font-weight:600; }
 main { padding:20px; max-width:720px; margin:0 auto; display:flex; flex-direction:column; gap:16px; }
 .form-group { display:flex; flex-direction:column; gap:8px; }
 label { font-weight:500; }
 input, textarea { width:100%; background:#111827; border:1px solid #374151; border-radius:8px; padding:12px; color:#f8fafc; font-size:14px; }
 textarea { min-height:200px; font-family: monospace; line-height:1.4; }
 button { align-self:flex-start; background:#2563eb; border:none; color:#f8fafc; padding:12px 20px; border-radius:8px; font-size:15px; cursor:pointer; }
 button:hover { background:#1d4ed8; }
 .status { padding:12px 16px; border-radius:8px; background:#111827; border:1px solid #374151; }
 .file-list { background:#111827; border-radius:8px; padding:16px; }
 .file-item { padding:8px 0; border-bottom:1px solid #374151; }
 .file-item:last-child { border-bottom:none; }
</style>
</head><body>
  <header>Панель управления DLL для чата</header>
  <main>
    <div class="form-group">
      <label for="fileName">Название файла (без расширения .dll):</label>
      <input type="text" id="fileName" placeholder="orange_chat_color" value="orange_chat_color">
    </div>
    
    <div class="form-group">
      <label for="dllCode">Код DLL библиотеки:</label>
      <textarea id="dllCode">#include &lt;string&gt;

extern "C" {
__declspec(dllexport) void apply_chat_modifications(std::string& message_type, std::string& color_code) {
    if (message_type == "ORANGE") {
        color_code = "\033[38;5;214m"; // Оранжевый цвет
    }
}

__declspec(dllexport) bool should_color_message(const std::string& username) {
    // Все сообщения окрашиваем в оранжевый
    return true;
}
}</textarea>
    </div>
    
    <div style="display:flex; gap:12px; align-items:center;">
      <button id="loadBtn">Загрузить DLL</button>
      <span id="status" class="status">Готов к загрузке</span>
    </div>

    <div class="file-list">
      <h3>Загруженные DLL файлы:</h3>
      <div id="fileList">
        <div class="file-item">Файлы появятся здесь после загрузки</div>
      </div>
    </div>
  </main>
<script>
const fileNameInput = document.getElementById('fileName');
const dllCodeInput = document.getElementById('dllCode');
const loadBtn = document.getElementById('loadBtn');
const statusEl = document.getElementById('status');
const fileListEl = document.getElementById('fileList');

async function loadDll() {
    const fileName = fileNameInput.value.trim();
    const dllCode = dllCodeInput.value.trim();
    
    if (!fileName) {
        setStatus('Ошибка: укажите название файла');
        return;
    }
    
    if (!dllCode) {
        setStatus('Ошибка: введите код DLL');
        return;
    }

    setStatus('Загрузка...');
    
    try {
        const response = await fetch('/load_dll', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                file_name: fileName,
                code: dllCode
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            setStatus('Успешно: ' + result.message);
            updateFileList();
        } else {
            setStatus('Ошибка: ' + result.error);
        }
    } catch (error) {
        setStatus('Ошибка сети: ' + error.message);
    }
}

async function updateFileList() {
    try {
        const response = await fetch('/list_files');
        const files = await response.json();
        
        if (files.length === 0) {
            fileListEl.innerHTML = '<div class="file-item">Нет загруженных файлов</div>';
            return;
        }
        
        fileListEl.innerHTML = files.map(file => 
            `<div class="file-item">${file}</div>`
        ).join('');
    } catch (error) {
        fileListEl.innerHTML = '<div class="file-item">Ошибка загрузки списка</div>';
    }
}

function setStatus(text) {
    statusEl.textContent = text;
}

loadBtn.addEventListener('click', loadDll);

// Загружаем список файлов при старте
updateFileList();
</script>
</body></html>)HTML";

// ========= Общее состояние чата с поддержкой DLL =========
struct SharedState {
    // онлайн: name -> session
    std::unordered_map<std::string, std::weak_ptr<class WSSession>> online;
    // ip -> last name
    std::unordered_map<std::string, std::string> last_name_by_ip;
    // owner -> set
    std::unordered_map<std::string, std::unordered_set<std::string>> blacklist;
    std::unordered_map<std::string, std::unordered_set<std::string>> favorites;
    // офлайн: recipient -> deque(sender,text)
    std::unordered_map<std::string, std::deque<std::pair<std::string,std::string>>> offline_inbox;
    
    // DLL функционал
    mutable std::mutex dll_mutex;
    std::atomic<bool> orange_color_enabled{false};
    std::string current_dll_name;
    
    void enable_orange_color(bool enabled) { 
        orange_color_enabled.store(enabled); 
    }
    
    bool is_orange_color_enabled() const { 
        return orange_color_enabled.load(); 
    }
    
    void set_current_dll(const std::string& dll_name) {
        std::lock_guard<std::mutex> lock(dll_mutex);
        current_dll_name = dll_name;
    }
    
    std::string get_current_dll() const {
        std::lock_guard<std::mutex> lock(dll_mutex);
        return current_dll_name;
    }
    
    bool is_blocked(const std::string& receiver, const std::string& sender) {
        auto it = blacklist.find(receiver);
        return it != blacklist.end() && it->second.count(sender);
    }

    void broadcast_public(const std::string& from, const std::string& text);
    void deliver_offline_if_any(const std::shared_ptr<class WSSession>& s);
};

// ========= WebSocket-сессия =========
class WSSession : public std::enable_shared_from_this<WSSession> {
public:
    WSSession(tcp::socket&& socket, std::shared_ptr<SharedState> state)
        : ws_(std::move(socket)), state_(std::move(state)) {}

    void do_accept(http::request<http::string_body> req) {
        req_ = std::move(req);
        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_.set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res){
                res.set(http::field::server, std::string(BOOST_BEAST_VERSION_STRING) + " chat");
            }));
        ws_.async_accept(req_, beast::bind_front_handler(&WSSession::on_accept, shared_from_this()));
    }

    void on_accept(beast::error_code ec) {
        if (ec) return;
        
        try {
            boost::system::error_code ec2;
            auto ep = ws_.next_layer().remote_endpoint(ec2);
            if (!ec2) {
                ip_ = ep.address().to_string();
            }
            auto it = state_->last_name_by_ip.find(ip_);
            if (it != state_->last_name_by_ip.end()) {
                send_text("SYS: Обнаружен прежний IP. Использовать прежнее имя \"" + it->second + "\"? Команда: #me " + it->second);
            } else {
                send_text("SYS: Введите имя: #me <name>");
            }
            
            // Уведомление о активных DLL
            if (state_->is_orange_color_enabled()) {
                send_text("SYS: Активна DLL: " + state_->get_current_dll() + " - оранжевый цвет чата включен!");
            }
        } catch (...) {
            send_text("SYS: Введите имя: #me <name>");
        }
        do_read();
    }

    void do_read() {
        ws_.async_read(buffer_, beast::bind_front_handler(&WSSession::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t) {
        if (ec) { on_close(); return; }
        std::string line = beast::buffers_to_string(buffer_.data());
        buffer_.consume(buffer_.size());
        handle_line(line);
        do_read();
    }

    void send_text(const std::string& s) {
        bool writing = !outbox_.empty();
        
        // Применяем оранжевый цвет если DLL активна
        std::string colored_message = s;
        if (state_->is_orange_color_enabled() && 
            (s.rfind("MSG:", 0) == 0 || s.rfind("FAV:", 0) == 0 || s.rfind("DM:", 0) == 0)) {
            colored_message = "ORANGE:" + s;
        }
        
        outbox_.push_back(colored_message);
        if (!writing) do_write();
    }

    void do_write() {
        ws_.text(true);
        ws_.async_write(
            boost::asio::buffer(outbox_.front()),
            beast::bind_front_handler(&WSSession::on_write, shared_from_this())
        );
    }

    void on_write(beast::error_code ec, std::size_t) {
        if (ec) { on_close(); return; }
        outbox_.pop_front();
        if (!outbox_.empty()) do_write();
    }

    void on_close() {
        if (!name_.empty()) {
            auto it = state_->online.find(name_);
            if (it != state_->online.end() && !it->second.expired()) {
                state_->online.erase(it);
            }
        }
    }

    const std::string& name() const { return name_; }

private:
    static std::string trim_after(const std::string& line, const std::string& cmd) {
        if (line.size() <= cmd.size()) return "";
        std::string rest = line.substr(cmd.size());
        size_t p = rest.find_first_not_of(" \t");
        if (p == std::string::npos) return "";
        return rest.substr(p);
    }

    void handle_line(std::string line) {
        while (!line.empty() && (line.back()=='\n' || line.back()=='\r')) line.pop_back();

        // Обработка команды #dll_status
        if (line == "#dll_status") {
            if (state_->is_orange_color_enabled()) {
                send_text("SYS: Активна DLL: " + state_->get_current_dll() + " - оранжевый цвет чата");
            } else {
                send_text("SYS: Нет активных DLL модификаций");
            }
            return;
        }

        // Остальная обработка команд (как раньше)
        if (line.rfind("#me", 0) == 0) {
            std::string newname = trim_after(line, "#me");
            if (newname.empty()) { send_text("SYS: формат: #me <name>"); return; }
            auto it = state_->online.find(newname);
            if (it != state_->online.end() && !it->second.expired() && it->second.lock().get() != this) {
                send_text("SYS: имя занято");
                return;
            }
            if (!name_.empty()) state_->online.erase(name_);
            name_ = newname;
            state_->online[name_] = weak_from_this();
            if (!ip_.empty()) state_->last_name_by_ip[ip_] = name_;
            send_text("SYS: имя установлено: " + name_);
            state_->deliver_offline_if_any(shared_from_this());
            return;
        }

        if (name_.empty()) { send_text("SYS: сначала укажите имя: #me <name>"); return; }

        if (line == "#help") {
            send_text("SYS: Команды: #help, #who, #me <name>, #block <user>, #unblock <user>, #fav <user>, #unfav <user>, #massdm <text>, #dll_status");
            send_text("SYS: ЛС: @user <text>");
            return;
        }

        // ... остальные команды (who, block, unblock, fav, unfav, massdm, @user) остаются без изменений
        if (line == "#who") {
            std::string out = "SYS: Online: ";
            bool first=true;
            for (auto& [n, w] : state_->online) {
                if (w.expired()) continue;
                if (!first) out += ", ";
                out += n; first=false;
            }
            send_text(out);
            return;
        }

        if (line.rfind("@", 0) == 0) {
            auto sp = line.find(' ');
            std::string to = (sp == std::string::npos) ? line.substr(1) : line.substr(1, sp-1);
            std::string text = (sp == std::string::npos) ? "" : line.substr(sp+1);
            if (to.empty() || text.empty()) { send_text("SYS: формат ЛС: @user <text>"); return; }

            if (auto it = state_->online.find(to); it != state_->online.end()) {
                if (auto recip = it->second.lock()) {
                    if (!state_->is_blocked(recip->name(), name_)) {
                        recip->send_text("DM: от " + name_ + ": " + text);
                    }
                    return;
                }
            }
            auto& box = state_->offline_inbox[to];
            if (box.size() >= 10) {
                send_text("SYS: ящик пользователя переполнен");
            } else {
                box.emplace_back(name_, text);
                send_text("SYS: сообщение сохранено в офлайн-ящике для " + to);
            }
            return;
        }

        // Обычное сообщение всем
        state_->broadcast_public(name_, line);
    }

private:
    websocket::stream<tcp::socket> ws_;
    beast::flat_buffer buffer_;
    std::deque<std::string> outbox_;
    std::shared_ptr<SharedState> state_;
    std::string name_;
    std::string ip_;
    friend struct SharedState;
    http::request<http::string_body> req_;
};

// Реализации SharedState
void SharedState::broadcast_public(const std::string& from, const std::string& text) {
    for (auto it = online.begin(); it != online.end(); ++it) {
        const std::string& name = it->first;
        auto s = it->second.lock();
        if (!s) continue;
        if (is_blocked(name, from)) continue;
        bool fav = favorites[name].count(from);
        std::string payload = (fav ? "FAV: " : "MSG: ") + from + ": " + text;
        s->send_text(payload);
    }
}

void SharedState::deliver_offline_if_any(const std::shared_ptr<WSSession>& s) {
    auto it = offline_inbox.find(s->name());
    if (it == offline_inbox.end()) return;
    for (auto& m : it->second) {
        if (!is_blocked(s->name(), m.first)) {
            s->send_text("DM: (офлайн) от " + m.first + ": " + m.second);
        }
    }
    offline_inbox.erase(it);
}

// ========= HTTP-сессия для чата =========
class HTTPSession : public std::enable_shared_from_this<HTTPSession> {
public:
    HTTPSession(tcp::socket&& socket, std::shared_ptr<SharedState> st)
        : stream_(std::move(socket)), state_(std::move(st)) {}

    void run() { do_read(); }

private:
    void do_read() {
        req_ = {};
        http::async_read(stream_, buffer_, req_,
            beast::bind_front_handler(&HTTPSession::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t) {
        if (ec == http::error::end_of_stream) return do_close();
        if (ec) return;

        if (websocket::is_upgrade(req_)) {
            auto ws = std::make_shared<WSSession>(stream_.release_socket(), state_);
            ws->do_accept(std::move(req_));
            return;
        }

        // Отдаем простую HTML страницу для чата
        auto res = std::make_shared<http::response<http::string_body>>(
            http::status::ok, req_.version()
        );
        res->set(http::field::server, "chat-beast");
        res->set(http::field::content_type, "text/html; charset=utf-8");
        res->keep_alive(req_.keep_alive());
        
        // Простая чат-страница
        res->body() = R"HTML(<!doctype html>
<html><head><title>Chat</title></head>
<body>
<h1>Web Chat</h1>
<p>Используйте клиентское приложение для доступа к чату</p>
<p>Текущие DLL модификации: )HTML" + (state_->is_orange_color_enabled() ? "Оранжевый цвет активен" : "Нет") + R"HTML(</p>
</body></html>)HTML";
        
        res->prepare_payload();
        auto self = shared_from_this();
        http::async_write(stream_, *res,
            [self, res](beast::error_code ec, std::size_t){
                boost::ignore_unused(ec);
                self->do_close();
            });
    }

    void do_close() {
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
    }

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    std::shared_ptr<SharedState> state_;
};

// ========= Admin HTTP сессия для управления DLL =========
class AdminHTTPSession : public std::enable_shared_from_this<AdminHTTPSession> {
public:
    AdminHTTPSession(tcp::socket&& socket, std::shared_ptr<SharedState> st)
        : stream_(std::move(socket)), state_(std::move(st)) {}

    void run() { do_read(); }

private:
    void do_read() {
        req_ = {};
        http::async_read(stream_, buffer_, req_,
            beast::bind_front_handler(&AdminHTTPSession::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t) {
        if (ec == http::error::end_of_stream) return do_close();
        if (ec) return;

        // Обработка загрузки DLL
        if (req_.method() == http::verb::post && req_.target() == "/load_dll") {
            handle_load_dll();
            return;
        }

        // Список файлов
        if (req_.method() == http::verb::get && req_.target() == "/list_files") {
            handle_list_files();
            return;
        }

        // Главная страница админки
        if (req_.method() == http::verb::get && (req_.target() == "/" || req_.target() == "/index.html")) {
            handle_index();
            return;
        }

        auto res = std::make_shared<http::response<http::string_body>>(http::status::not_found, req_.version());
        res->set(http::field::server, "chat-admin");
        res->set(http::field::content_type, "text/plain; charset=utf-8");
        res->keep_alive(false);
        res->body() = "Неизвестный запрос";
        res->prepare_payload();
        write_response(res);
    }

    void handle_index() {
        auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
        res->set(http::field::server, "chat-admin");
        res->set(http::field::content_type, "text/html; charset=utf-8");
        res->keep_alive(req_.keep_alive());
        res->body() = ADMIN_HTML;
        res->prepare_payload();
        write_response(res);
    }

    void handle_load_dll() {
        try {
            // Парсим JSON
            auto body = req_.body();
            size_t start = body.find("\"file_name\":\"") + 12;
            size_t end = body.find("\"", start);
            std::string file_name = body.substr(start, end - start);
            
            start = body.find("\"code\":\"") + 8;
            end = body.find("\"", start);
            std::string code = body.substr(start, end - start);
            
            // Сохраняем файл
            std::ofstream file("dll_" + file_name + ".cpp");
            file << code;
            file.close();
            
            // Активируем функционал оранжевого цвета
            state_->enable_orange_color(true);
            state_->set_current_dll(file_name);
            
            // Логируем в консоль
            std::cout << "=== НОВАЯ DLL ЗАГРУЖЕНА ===" << std::endl;
            std::cout << "Файл: dll_" << file_name << ".cpp" << std::endl;
            std::cout << "Функционал: Оранжевый цвет чата активирован!" << std::endl;
            std::cout << "==========================" << std::endl;
            
            auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
            res->set(http::field::server, "chat-admin");
            res->set(http::field::content_type, "application/json");
            res->keep_alive(false);
            res->body() = "{\"message\": \"DLL успешно загружена и активирована. Оранжевый цвет чата включен!\"}";
            res->prepare_payload();
            write_response(res);
            
        } catch (const std::exception& e) {
            auto res = std::make_shared<http::response<http::string_body>>(http::status::bad_request, req_.version());
            res->set(http::field::server, "chat-admin");
            res->set(http::field::content_type, "application/json");
            res->keep_alive(false);
            res->body() = "{\"error\": \"Ошибка загрузки: " + std::string(e.what()) + "\"}";
            res->prepare_payload();
            write_response(res);
        }
    }

    void handle_list_files() {
        // Простой список файлов (в реальной системе нужно сканировать директорию)
        auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
        res->set(http::field::server, "chat-admin");
        res->set(http::field::content_type, "application/json");
        res->keep_alive(false);
        
        if (state_->is_orange_color_enabled()) {
            res->body() = "[\"dll_" + state_->get_current_dll() + ".cpp\"]";
        } else {
            res->body() = "[]";
        }
        
        res->prepare_payload();
        write_response(res);
    }

    void write_response(const std::shared_ptr<http::response<http::string_body>>& res) {
        auto self = shared_from_this();
        http::async_write(stream_, *res,
            [self, res](beast::error_code, std::size_t) {
                self->do_close();
            });
    }

    void do_close() {
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
    }

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    std::shared_ptr<SharedState> state_;
};

// ========= Listener для чата =========
class Listener : public std::enable_shared_from_this<Listener> {
public:
    Listener(boost::asio::io_context& ioc, tcp::endpoint ep, std::shared_ptr<SharedState> st)
        : ioc_(ioc), acceptor_(ioc), state_(std::move(st)) {
        beast::error_code ec;
        acceptor_.open(ep.protocol(), ec);
        if (ec) throw std::runtime_error("Listener open failed: " + ec.message());
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
        acceptor_.bind(ep, ec);
        if (ec) throw std::runtime_error("Listener bind failed: " + ec.message());
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) throw std::runtime_error("Listener listen failed: " + ec.message());
    }

    void run() { do_accept(); }

private:
    void do_accept() {
        acceptor_.async_accept(
            boost::asio::make_strand(ioc_),
            beast::bind_front_handler(&Listener::on_accept, shared_from_this()));
    }

    void on_accept(beast::error_code ec, tcp::socket socket) {
        if (ec) {
            std::cerr << "accept error: " << ec.message() << "\n";
            return do_accept();
        }
        std::make_shared<HTTPSession>(std::move(socket), state_)->run();
        do_accept();
    }

    boost::asio::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<SharedState> state_;
};

// ========= Admin Listener =========
class AdminListener : public std::enable_shared_from_this<AdminListener> {
public:
    AdminListener(boost::asio::io_context& ioc, tcp::endpoint ep, std::shared_ptr<SharedState> st)
        : ioc_(ioc), acceptor_(ioc), state_(std::move(st)) {
        beast::error_code ec;
        acceptor_.open(ep.protocol(), ec);
        if (ec) throw std::runtime_error("AdminListener open failed: " + ec.message());
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
        acceptor_.bind(ep, ec);
        if (ec) throw std::runtime_error("AdminListener bind failed: " + ec.message());
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) throw std::runtime_error("AdminListener listen failed: " + ec.message());
    }

    void run() { do_accept(); }

private:
    void do_accept() {
        acceptor_.async_accept(
            boost::asio::make_strand(ioc_),
            beast::bind_front_handler(&AdminListener::on_accept, shared_from_this()));
    }

    void on_accept(beast::error_code ec, tcp::socket socket) {
        if (ec) {
            std::cerr << "admin accept error: " << ec.message() << "\n";
            return do_accept();
        }
        std::make_shared<AdminHTTPSession>(std::move(socket), state_)->run();
        do_accept();
    }

    boost::asio::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<SharedState> state_;
};

int main(int argc, char** argv) {
    try {
#if defined(SIGPIPE)
        std::signal(SIGPIPE, SIG_IGN);
#endif
        unsigned short admin_port = 80;
        unsigned short chat_port = 8080;
        
        if (argc >= 2) admin_port = static_cast<unsigned short>(std::stoi(argv[1]));
        if (argc >= 3) chat_port = static_cast<unsigned short>(std::stoi(argv[2]));
        
        boost::asio::io_context ioc;
        auto state = std::make_shared<SharedState>();
        
        auto chat_ep = tcp::endpoint(tcp::v4(), chat_port);
        auto admin_ep = tcp::endpoint(tcp::v4(), admin_port);
        
        auto chat_listener = std::make_shared<Listener>(ioc, chat_ep, state);
        chat_listener->run();
        
        auto admin_listener = std::make_shared<AdminListener>(ioc, admin_ep, state);
        admin_listener->run();
        
        std::cout << "=== Chat Server Started ===" << std::endl;
        std::cout << "Web Chat UI: http://localhost:" << chat_port << std::endl;
        std::cout << "DLL Admin Panel: http://localhost:" << admin_port << std::endl;
        std::cout << "==========================" << std::endl;
        
        ioc.run();
    } catch (const std::exception& e) {
        std::cerr << "server_web error: " << e.what() << "\n";
        return 1;
    }
}