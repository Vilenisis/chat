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
#include <filesystem>
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
namespace fs = std::filesystem;
using namespace std;

static const std::string DLL_STORAGE_DIR = "dll_files";

struct MultipartPart {
    std::string name;
    std::string filename;
    std::string content;
};

static std::string trim_extension(const std::string& filename) {
    auto pos = filename.find_last_of('.');
    if (pos == std::string::npos) return filename;
    return filename.substr(0, pos);
}

static std::string extract_json_value(const std::string& body, const std::string& key) {
    const std::string pattern = "\"" + key + "\"";
    auto pos = body.find(pattern);
    if (pos == std::string::npos) return {};
    pos = body.find('"', pos + pattern.size());
    if (pos == std::string::npos) return {};
    auto end = body.find('"', pos + 1);
    if (end == std::string::npos || end <= pos + 1) return {};
    return body.substr(pos + 1, end - pos - 1);
}

static std::string extract_boundary(const std::string& content_type) {
    const std::string boundary_key = "boundary=";
    auto pos = content_type.find(boundary_key);
    if (pos == std::string::npos) return {};
    return content_type.substr(pos + boundary_key.size());
}

static std::vector<MultipartPart> parse_multipart(const std::string& body, const std::string& boundary) {
    std::vector<MultipartPart> parts;
    const std::string delimiter = "--" + boundary;
    size_t pos = 0;

    while (true) {
        size_t start = body.find(delimiter, pos);
        if (start == std::string::npos) break;
        start += delimiter.size();

        if (start + 2 <= body.size() && body.compare(start, 2, "--") == 0) break;
        if (start + 2 <= body.size() && body.compare(start, 2, "\r\n") == 0) start += 2;

        size_t header_end = body.find("\r\n\r\n", start);
        if (header_end == std::string::npos) break;
        std::string header_section = body.substr(start, header_end - start);

        size_t content_start = header_end + 4;
        size_t next = body.find(delimiter, content_start);
        if (next == std::string::npos) break;
        size_t content_end = next;
        if (content_end >= 2 && body[content_end - 2] == '\r' && body[content_end - 1] == '\n') {
            content_end -= 2;
        }

        MultipartPart part;
        std::istringstream header_stream(header_section);
        std::string header_line;
        while (std::getline(header_stream, header_line)) {
            if (!header_line.empty() && header_line.back() == '\r') header_line.pop_back();
            std::string lower_header = header_line;
            std::transform(lower_header.begin(), lower_header.end(), lower_header.begin(), ::tolower);
            if (lower_header.find("content-disposition") != std::string::npos) {
                auto name_pos = header_line.find("name=");
                if (name_pos != std::string::npos) {
                    auto start_name = header_line.find('"', name_pos);
                    auto end_name = header_line.find('"', start_name + 1);
                    if (start_name != std::string::npos && end_name != std::string::npos) {
                        part.name = header_line.substr(start_name + 1, end_name - start_name - 1);
                    }
                }
                auto file_pos = header_line.find("filename=");
                if (file_pos != std::string::npos) {
                    auto start_file = header_line.find('"', file_pos);
                    auto end_file = header_line.find('"', start_file + 1);
                    if (start_file != std::string::npos && end_file != std::string::npos) {
                        part.filename = header_line.substr(start_file + 1, end_file - start_file - 1);
                    }
                }
            }
        }

        part.content = body.substr(content_start, content_end - content_start);
        parts.push_back(std::move(part));
        pos = next;
    }

    return parts;
}

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
      <label for="dllFile">Выберите DLL файл для загрузки:</label>
      <input type="file" id="dllFile" accept=".dll,.bin,.dat,.cpp">
      <small style="color:#94a3b8;">Можно выбрать готовый DLL или .cpp файл с исходниками.</small>
    </div>

    <div class="form-group">
      <label for="fileName">Название файла (без расширения):</label>
      <input type="text" id="fileName" placeholder="orange_chat_color" value="orange_chat_color">
      <small style="color:#94a3b8;">Название можно изменить перед загрузкой — оно будет использовано для сохранения файлов.</small>
    </div>

    <div class="form-group">
      <label for="dllCode">Редактируемый код DLL (необязательно, сохранится рядом с файлом):</label>
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
      <small style="color:#94a3b8;">Можно загрузить файл и параллельно обновить код — он сохранится как .cpp с выбранным именем.</small>
    </div>

    <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
      <button id="loadBtn">Загрузить DLL</button>
      <span id="status" class="status">Готов к загрузке</span>
    </div>

    <div class="status" id="dllInfo">
      Активная библиотека: нет данных. Порт веб-загрузки: 80, чат слушает порт 8080 (открывайте два терминальных клиента для проверки изменений).
    </div>

    <div class="file-list">
      <h3>Загруженные файлы:</h3>
      <div id="fileList">
        <div class="file-item">Файлы появятся здесь после загрузки</div>
      </div>
    </div>
  </main>
<script>
const fileNameInput = document.getElementById('fileName');
const dllCodeInput = document.getElementById('dllCode');
const dllFileInput = document.getElementById('dllFile');
const loadBtn = document.getElementById('loadBtn');
const statusEl = document.getElementById('status');
const fileListEl = document.getElementById('fileList');
const dllInfoEl = document.getElementById('dllInfo');

dllFileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const baseName = file.name.replace(/\.[^.]+$/, '');
    if (!fileNameInput.value.trim()) {
        fileNameInput.value = baseName;
    }

    if (file.type.startsWith('text') || file.name.endsWith('.cpp')) {
        try {
            const text = await file.text();
            dllCodeInput.value = text;
        } catch (e) {
            setStatus('Не удалось прочитать файл: ' + e.message);
        }
    }
});

async function loadDll() {
    const fileName = fileNameInput.value.trim();
    const dllCode = dllCodeInput.value.trim();
    const dllFile = dllFileInput.files[0];

    if (!fileName) {
        setStatus('Ошибка: укажите название файла');
        return;
    }

    if (!dllFile && !dllCode) {
        setStatus('Ошибка: выберите файл или введите код');
        return;
    }

    setStatus('Загрузка...');

    try {
        const formData = new FormData();
        formData.append('file_name', fileName);
        formData.append('code', dllCode);
        if (dllFile) {
            formData.append('dll_file', dllFile);
        }

        const response = await fetch('/upload_dll', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (response.ok) {
            setStatus('Успешно: ' + result.message);
            updateFileList();
            updateDllStatus();
            dllFileInput.value = '';
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

        if (!files || files.length === 0) {
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

async function updateDllStatus() {
    try {
        const response = await fetch('/dll_status');
        const data = await response.json();
        const dllName = data.active || 'нет активной библиотеки';
        const colorState = data.orange ? 'оранжевый цвет включен' : 'оранжевый цвет отключен';
        dllInfoEl.textContent = `Активная библиотека: ${dllName}; ${colorState}. Веб-загрузка на порту 80, чат на порту 8080.`;
    } catch (error) {
        dllInfoEl.textContent = 'Не удалось получить статус DLL';
    }
}

function setStatus(text) {
    statusEl.textContent = text;
}

loadBtn.addEventListener('click', loadDll);

// Загружаем список файлов при старте
updateFileList();
updateDllStatus();
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

    void notify_dll_event(const std::string& message);
    
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
        if (ec) {
            std::cerr << "WebSocket accept error: " << ec.message() << std::endl;
            return;
        }
        std::cout << "WebSocket connection accepted" << std::endl;
        do_read();
    }

    void do_read() {
        ws_.async_read(buffer_, beast::bind_front_handler(&WSSession::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t) {
        if (ec) {
            std::cerr << "WebSocket read error: " << ec.message() << std::endl;
            on_close();
            return;
        }
        std::string line = beast::buffers_to_string(buffer_.data());
        std::cout << "Received message: " << line << std::endl;
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
        std::cout << "Handling line: " << line << std::endl;
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();

        try {
            if (line == "#help") {
                send_text("SYS: Команды: #help, #who, #me <name>, #block <user>, #unblock <user>, #fav <user>, #unfav <user>, #massdm <text>, #dll_status");
                send_text("SYS: ЛС: @user <text>");
                return;
            }

            if (line.rfind("#me", 0) == 0) {
                std::string newname = trim_after(line, "#me");
                if (newname.empty()) {
                    send_text("SYS: Укажите имя после команды #me");
                    return;
                }
                auto it = state_->online.find(newname);
                if (it != state_->online.end() && !it->second.expired() && it->second.lock().get() != this) {
                    send_text("SYS: Имя уже занято");
                    return;
                }
                if (!name_.empty()) {
                    state_->online.erase(name_);
                }
                name_ = newname;
                state_->online[name_] = weak_from_this();
                send_text("SYS: Имя установлено: " + name_);
                state_->deliver_offline_if_any(shared_from_this());
                return;
            }

            if (name_.empty()) {
                send_text("SYS: Сначала укажите имя: #me <name>");
                return;
            }

            // Обработка других команд...
            state_->broadcast_public(name_, line);

        } catch (const std::exception& e) {
            std::cerr << "Error in handle_line: " << e.what() << std::endl;
            send_text("SYS: Произошла ошибка при обработке команды");
        }
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

void SharedState::notify_dll_event(const std::string& message) {
    for (auto it = online.begin(); it != online.end(); ++it) {
        auto s = it->second.lock();
        if (!s) continue;
        s->send_text("SYS: " + message);
    }
}

// Реализации SharedState
void SharedState::broadcast_public(const std::string& from, const std::string& text) {
    try {
        for (auto it = online.begin(); it != online.end(); ++it) {
            const std::string& name = it->first;
            auto s = it->second.lock();
            if (!s) continue;
            if (is_blocked(name, from)) continue;
            bool fav = favorites[name].count(from);
            std::string payload = (fav ? "FAV: " : "MSG: ") + from + ": " + text;
            s->send_text(payload);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in broadcast_public: " << e.what() << std::endl;
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
        std::string status_html = R"HTML(<!doctype html>
        <html><head><title>Chat</title></head>
        <body>
        <h1>Web Chat</h1>
        <p>Используйте клиентское приложение для доступа к чату</p>
        <p>Текущие DLL модификации: )HTML";
        status_html += (state_->is_orange_color_enabled() ? "Оранжевый цвет активен" : "Нет");
        status_html += R"HTML(</p>
        </body></html>)HTML";

        res->body() = status_html;
        
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
        if (req_.method() == http::verb::post && req_.target() == "/upload_dll") {
            handle_upload_dll();
            return;
        }

        if (req_.method() == http::verb::post && req_.target() == "/load_dll") {
            handle_load_dll();
            return;
        }

        // Список файлов
        if (req_.method() == http::verb::get && req_.target() == "/list_files") {
            handle_list_files();
            return;
        }

        // Статус активной DLL
        if (req_.method() == http::verb::get && req_.target() == "/dll_status") {
            handle_dll_status();
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
        res->keep_alive(req_.keep_alive());
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

    void handle_upload_dll() {
        try {
            const std::string content_type = std::string(req_[http::field::content_type]);
            if (content_type.find("multipart/form-data") == std::string::npos) {
                throw std::runtime_error("Ожидался multipart/form-data");
            }

            const std::string boundary = extract_boundary(content_type);
            if (boundary.empty()) {
                throw std::runtime_error("Граница multipart не найдена");
            }

            auto parts = parse_multipart(req_.body(), boundary);
            std::string provided_name;
            std::string code_content;
            MultipartPart dll_part;
            bool has_file = false;

            for (const auto& part : parts) {
                if (part.name == "file_name" && !part.content.empty()) {
                    provided_name = part.content;
                } else if (part.name == "code") {
                    code_content = part.content;
                } else if (part.name == "dll_file") {
                    dll_part = part;
                    has_file = true;
                }
            }

            if (!has_file && code_content.empty()) {
                throw std::runtime_error("Необходимо выбрать файл или указать код DLL");
            }

            std::string final_name;
            if (!provided_name.empty()) {
                final_name = provided_name;
            } else if (has_file && !dll_part.filename.empty()) {
                final_name = trim_extension(dll_part.filename);
            }

            if (final_name.empty()) {
                throw std::runtime_error("Не удалось определить имя файла");
            }

            fs::create_directories(DLL_STORAGE_DIR);
            std::vector<std::string> saved_entries;

            if (has_file) {
                std::string extension = ".dll";
                auto pos = dll_part.filename.find_last_of('.');
                if (pos != std::string::npos) {
                    extension = dll_part.filename.substr(pos);
                }
                auto dll_path = fs::path(DLL_STORAGE_DIR) / (final_name + extension);
                std::ofstream output(dll_path, std::ios::binary);
                output.write(dll_part.content.data(), static_cast<std::streamsize>(dll_part.content.size()));
                output.close();
                saved_entries.push_back(dll_path.filename().string());
            }

            if (!code_content.empty()) {
                auto code_path = fs::path(DLL_STORAGE_DIR) / (final_name + ".cpp");
                std::ofstream code_file(code_path, std::ios::binary);
                code_file.write(code_content.data(), static_cast<std::streamsize>(code_content.size()));
                code_file.close();
                saved_entries.push_back(code_path.filename().string());
            }

            state_->enable_orange_color(true);
            state_->set_current_dll(final_name);
            state_->notify_dll_event("Загружена новая библиотека '" + final_name + "' (" + std::to_string(saved_entries.size()) + " файл(ов))");

            auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
            res->set(http::field::server, "chat-admin");
            res->set(http::field::content_type, "application/json");
            res->keep_alive(req_.keep_alive());

            std::ostringstream body;
            body << "{\"message\":\"Загрузка завершена\",\"saved\":[";
            for (size_t i = 0; i < saved_entries.size(); ++i) {
                body << "\"" << saved_entries[i] << "\"";
                if (i + 1 < saved_entries.size()) body << ",";
            }
            body << "]}";
            res->body() = body.str();
            res->prepare_payload();
            write_response(res);

        } catch (const std::exception& e) {
            auto res = std::make_shared<http::response<http::string_body>>(http::status::bad_request, req_.version());
            res->set(http::field::server, "chat-admin");
            res->set(http::field::content_type, "application/json");
            res->keep_alive(req_.keep_alive());
            res->body() = "{\"error\":\"" + std::string(e.what()) + "\"}";
            res->prepare_payload();
            write_response(res);
        }
    }

    void handle_load_dll() {
        try {
            const auto body = req_.body();
            const std::string file_name = extract_json_value(body, "file_name");
            const std::string code = extract_json_value(body, "code");

            if (file_name.empty() || code.empty()) {
                throw std::runtime_error("Передайте file_name и code");
            }

            fs::create_directories(DLL_STORAGE_DIR);

            // Сохраняем файл
            auto path = fs::path(DLL_STORAGE_DIR) / (file_name + ".cpp");
            std::ofstream file(path);
            file << code;
            file.close();

            // Активируем функционал оранжевого цвета
            state_->enable_orange_color(true);
            state_->set_current_dll(file_name);
            state_->notify_dll_event("Загружена новая библиотека '" + file_name + "' из редактора кода");

            // Логируем в консоль
            std::cout << "=== НОВАЯ DLL ЗАГРУЖЕНА ===" << std::endl;
            std::cout << "Файл: " << path << std::endl;
            std::cout << "Функционал: Оранжевый цвет чата активирован!" << std::endl;
            std::cout << "==========================" << std::endl;
            
            auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
            res->set(http::field::server, "chat-admin");
            res->set(http::field::content_type, "application/json");
            res->keep_alive(req_.keep_alive());
            res->body() = "{\"message\": \"DLL успешно загружена и активирована. Оранжевый цвет чата включен!\"}";
            res->prepare_payload();
            write_response(res);
            
        } catch (const std::exception& e) {
            auto res = std::make_shared<http::response<http::string_body>>(http::status::bad_request, req_.version());
            res->set(http::field::server, "chat-admin");
            res->set(http::field::content_type, "application/json");
            res->keep_alive(req_.keep_alive());
            res->body() = "{\"error\": \"Ошибка загрузки: " + std::string(e.what()) + "\"}";
            res->prepare_payload();
            write_response(res);
        }
    }

    void handle_list_files() {
        auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
        res->set(http::field::server, "chat-admin");
        res->set(http::field::content_type, "application/json");
        res->keep_alive(req_.keep_alive());

        std::ostringstream body;
        body << "[";

        bool first = true;
        if (fs::exists(DLL_STORAGE_DIR)) {
            for (const auto& entry : fs::directory_iterator(DLL_STORAGE_DIR)) {
                if (!entry.is_regular_file()) continue;
                if (!first) body << ",";
                body << "\"" << entry.path().filename().string() << "\"";
                first = false;
            }
        }

        body << "]";
        res->body() = body.str();

        res->prepare_payload();
        write_response(res);
    }

    void handle_dll_status() {
        auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
        res->set(http::field::server, "chat-admin");
        res->set(http::field::content_type, "application/json");
        res->keep_alive(req_.keep_alive());

        const auto current = state_->get_current_dll();
        std::ostringstream body;
        body << "{\"active\":\"" << current << "\",";
        body << "\"orange\":" << (state_->is_orange_color_enabled() ? "true" : "false") << "}";
        res->body() = body.str();
        res->prepare_payload();
        write_response(res);
    }

    void write_response(const std::shared_ptr<http::response<http::string_body>>& res) {
        auto self = shared_from_this();
        http::async_write(stream_, *res,
            [self, res](beast::error_code, std::size_t) {
                if (res->need_eof()) self->do_close();
                else self->do_read();
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