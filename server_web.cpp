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

// Встроенная страница (минимальный UI)
static const char* INDEX_HTML = R"HTML(<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Chat</title>
<style>
 body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin:0; background:#0f172a; color:#e2e8f0; }
 header { padding:12px 16px; background:#111827; border-bottom:1px solid #374151; }
 main { display:flex; height: calc(100vh - 56px); }
 #log { flex:1; padding:16px; overflow:auto; }
 .sys { color:#60a5fa; }
 .dm  { color:#34d399; }
 .fav { color:#f59e0b; }
 .msg { color:#e2e8f0; }
 footer { position:fixed; bottom:0; left:0; right:0; display:flex; gap:8px; padding:12px; background:#111827; border-top:1px solid #374151; }
 input, button { font-size:16px; padding:10px 12px; border-radius:10px; border:1px solid #374151; background:#0b1220; color:#e2e8f0; }
 button { background:#2563eb; border:none; }
 #nameBar { margin-left:8px; opacity:.7; font-size:12px; }
</style>
</head><body>
  <header>Web Chat <span id="nameBar"></span></header>
  <main><pre id="log"></pre></main>
  <footer>
    <input id="input" placeholder="Напишите сообщение или команду (#help, #me, @user ...)" style="flex:1" />
    <button id="send">Отправить</button>
  </footer>
<script>
const log = document.getElementById('log');
const input = document.getElementById('input');
const sendBtn = document.getElementById('send');
const nameBar = document.getElementById('nameBar');

function append(line, cls) {
  const span = document.createElement('div');
  span.textContent = line;
  span.className = cls;
  log.appendChild(span);
  log.scrollTop = log.scrollHeight;
  if (line.startsWith('SYS: имя установлено: ')) {
    nameBar.textContent = '— вы: ' + line.replace('SYS: имя установлено: ', '');
  }
}
const proto = location.protocol === 'https:' ? 'wss' : 'ws';
const ws = new WebSocket(proto + '://' + location.host + '/ws');

ws.addEventListener('open', () => append('SYS: подключено, введите имя: #me <name>', 'sys'));
ws.addEventListener('message', (ev) => {
  const line = ev.data;
  if (line.startsWith('SYS:')) append(line, 'sys');
  else if (line.startsWith('DM:')) append(line, 'dm');
  else if (line.startsWith('FAV:')) append(line, 'fav');
  else append(line, 'msg');
});
ws.addEventListener('close', () => append('SYS: соединение закрыто', 'sys'));
ws.addEventListener('error', () => append('SYS: ошибка сокета', 'sys'));

function send() {
  if (input.value.trim() === '') return;
  ws.send(input.value);
  input.value = '';
  input.focus();
}
sendBtn.addEventListener('click', send);
input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
</script>
</body></html>)HTML";

static const char* ADMIN_HTML_TEMPLATE_HEAD = R"HTML(<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Chat Admin</title>
<style>
 body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin:0; background:#030712; color:#e5e7eb; }
 header { padding:16px; background:#0f172a; border-bottom:1px solid #1f2937; font-size:20px; font-weight:600; }
 main { padding:20px; max-width:720px; margin:0 auto; display:flex; flex-direction:column; gap:16px; }
 textarea { width:100%; min-height:200px; background:#111827; border:1px solid #374151; border-radius:12px; padding:12px; color:#f8fafc; font-size:14px; line-height:1.4; }
 button { align-self:flex-start; background:#2563eb; border:none; color:#f8fafc; padding:12px 20px; border-radius:12px; font-size:15px; cursor:pointer; }
 button:hover { background:#1d4ed8; }
 .status { padding:12px 16px; border-radius:12px; background:#111827; border:1px solid #374151; }
</style>
</head><body>
  <header>Панель администратора чата</header>
  <main>
    <p>Загрузите обновление DLL: вставьте текст скрипта (например, вызов <code>repeat_last_message_twice</code>) и нажмите «Load».</p>
    <label for="dllInput">DLL script</label>
    <textarea id="dllInput">)HTML";

static const char* ADMIN_HTML_TEMPLATE_TAIL = R"HTML(
    <div style="display:flex; gap:12px; align-items:center;">
      <button id="loadBtn">Load</button>
      <span id="status" class="status"></span>
    </div>
  </main>
<script>
const dllInput = document.getElementById('dllInput');
const loadBtn = document.getElementById('loadBtn');
const statusEl = document.getElementById('status');

function setStatus(text) {
  statusEl.textContent = text;
}

function loadDll() {
  fetch('/load', {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain;charset=utf-8' },
    body: dllInput.value
  }).then(async (res) => {
    const txt = await res.text();
    setStatus(txt);
  }).catch(() => setStatus('Ошибка загрузки DLL'));
}

loadBtn.addEventListener('click', loadDll);
setStatus(window.__ADMIN_STATUS__ || 'Готово');
</script>
</body></html>)HTML";

static std::string html_escape(const std::string& input) {
  std::string out;
  out.reserve(input.size());
  for (char c : input) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out += c; break;
    }
  }
  return out;
}

static std::string js_escape(const std::string& input) {
  std::string out;
  out.reserve(input.size());
  for (char c : input) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '\'': out += "\\'"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      default: out += c; break;
    }
  }
  return out;
}

// ========= Общее состояние чата =========
struct Message { std::string from, text; };

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
  std::atomic<bool> repeat_last_message_twice{false};
  mutable std::mutex script_mutex;
  std::string last_loaded_script;

  bool is_blocked(const std::string& receiver, const std::string& sender) {
    auto it = blacklist.find(receiver);
    return it != blacklist.end() && it->second.count(sender);
  }

  void broadcast_public(const std::string& from, const std::string& text);
  void deliver_offline_if_any(const std::shared_ptr<class WSSession>& s);

  void enable_repeat_last_message(bool value) { repeat_last_message_twice.store(value); }
  bool repeat_enabled() const { return repeat_last_message_twice.load(); }
  void update_last_script(std::string script) {
    std::lock_guard<std::mutex> lock(script_mutex);
    last_loaded_script = std::move(script);
  }
  std::string last_script() const {
    std::lock_guard<std::mutex> lock(script_mutex);
    return last_loaded_script;
  }
};

static std::string render_admin_page(const std::shared_ptr<SharedState>& state) {
  std::ostringstream page;
  page << ADMIN_HTML_TEMPLATE_HEAD;
  page << html_escape(state->last_script());
  page << "\n</textarea>\n";
  std::string status = state->repeat_enabled()
    ? "Повтор последнего сообщения включен"
    : "Повтор последнего сообщения отключен";
  page << "    <script>window.__ADMIN_STATUS__ = '" << js_escape(status) << "';</script>\n";
  page << ADMIN_HTML_TEMPLATE_TAIL;
  return page.str();
}

// ========= WebSocket-сессия =========
class WSSession : public std::enable_shared_from_this<WSSession> {
public:
  WSSession(tcp::socket&& socket, std::shared_ptr<SharedState> state)
    : ws_(std::move(socket)), state_(std::move(state)) {}

  void do_accept(http::request<http::string_body> req) {
    req_ = std::move(req); // сохранить до колбэка
    ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
    ws_.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res){
        res.set(http::field::server, std::string(BOOST_BEAST_VERSION_STRING) + " chat");
        }));
    ws_.async_accept(req_, beast::bind_front_handler(&WSSession::on_accept, shared_from_this()));
  }


  void on_accept(beast::error_code ec) {
    if (ec) return;
    // приветствие + подсказка имени по IP
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

    // обработка команд
    handle_line(line);
    do_read();
  }

  void send_text(const std::string& s) {
    // Поставим в очередь, чтобы не нарушать порядок при async_write
    bool writing = !outbox_.empty();
    outbox_.push_back(s);
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
    // удалим из онлайна
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
    // Снимем \r\n
    while (!line.empty() && (line.back()=='\n' || line.back()=='\r')) line.pop_back();

    if (line.rfind("#me", 0) == 0) {
      std::string newname = trim_after(line, "#me");
      if (newname.empty()) { send_text("SYS: формат: #me <name>"); return; }
      // проверка занятости
      auto it = state_->online.find(newname);
      if (it != state_->online.end() && !it->second.expired() && it->second.lock().get() != this) {
        send_text("SYS: имя занято");
        return;
      }
      // снять старое имя
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
      send_text("SYS: Команды: #help, #who, #me <name>, #block <user>, #unblock <user>, #fav <user>, #unfav <user>, #massdm <text>");
      send_text("SYS: ЛС: @user <text>");
      return;
    }

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

    if (line.rfind("#block", 0) == 0) {
      std::string who = trim_after(line, "#block");
      if (who.empty() || who == name_) { send_text("SYS: #block <user>"); return; }
      state_->blacklist[name_].insert(who);
      send_text("SYS: добавлен в ЧС: " + who);
      return;
    }
    if (line.rfind("#unblock", 0) == 0) {
      std::string who = trim_after(line, "#unblock");
      if (who.empty()) { send_text("SYS: #unblock <user>"); return; }
      auto& set = state_->blacklist[name_];
      if (set.erase(who)) send_text("SYS: удалён из ЧС: " + who);
      else send_text("SYS: не был в ЧС: " + who);
      return;
    }

    if (line.rfind("#fav", 0) == 0) {
      std::string who = trim_after(line, "#fav");
      if (who.empty() || who == name_) { send_text("SYS: #fav <user>"); return; }
      state_->favorites[name_].insert(who);
      send_text("SYS: добавлен в любимые: " + who);
      return;
    }
    if (line.rfind("#unfav", 0) == 0) {
      std::string who = trim_after(line, "#unfav");
      if (who.empty()) { send_text("SYS: #unfav <user>"); return; }
      auto& set = state_->favorites[name_];
      if (set.erase(who)) send_text("SYS: удалён из любимых: " + who);
      else send_text("SYS: не был в любимых: " + who);
      return;
    }

    if (line.rfind("#massdm", 0) == 0) {
      std::string text = trim_after(line, "#massdm");
      if (text.empty()) { send_text("SYS: #massdm <text>"); return; }
      for (auto& [n, w] : state_->online) {
        if (n == name_) continue;
        auto s = w.lock();
        if (!s) continue;
        if (state_->is_blocked(n, name_)) continue;
        s->send_text("DM: от " + name_ + ": " + text);
      }
      return;
    }

    if (line.rfind("@", 0) == 0) {
      auto sp = line.find(' ');
      std::string to = (sp == std::string::npos) ? line.substr(1) : line.substr(1, sp-1);
      std::string text = (sp == std::string::npos) ? "" : line.substr(sp+1);
      if (to.empty() || text.empty()) { send_text("SYS: формат ЛС: @user <text>"); return; }

      // онлайн?
      if (auto it = state_->online.find(to); it != state_->online.end()) {
        if (auto recip = it->second.lock()) {
          if (!state_->is_blocked(recip->name(), name_)) {
            recip->send_text("DM: от " + name_ + ": " + text);
          }
          return;
        }
      }
      // офлайн
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

// Реализации SharedState, зависящие от WSSession
void SharedState::broadcast_public(const std::string& from, const std::string& text) {
  for (auto it = online.begin(); it != online.end(); ++it) {
    const std::string& name = it->first;
    auto s = it->second.lock();
    if (!s) continue;
    if (is_blocked(name, from)) continue;
    bool fav = favorites[name].count(from);
    std::string payload = (fav ? "FAV: " : "MSG: ") + from + ": " + text;
    s->send_text(payload);
    if (repeat_enabled()) {
      s->send_text(payload);
    }
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

// ========= HTTP-сессия (детектируем апгрейд на WS) =========
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

    // Если запрос на апгрейд в WebSocket → передаём управление WSSession
    if (websocket::is_upgrade(req_)) {
      auto ws = std::make_shared<WSSession>(stream_.release_socket(), state_);
      ws->do_accept(std::move(req_));
      return;
    }

    // Иначе отдаём index.html
    auto res = std::make_shared<http::response<http::string_body>>(
      http::status::ok, req_.version()
    );
    res->set(http::field::server, "chat-beast");
    res->set(http::field::content_type, "text/html; charset=utf-8");
    res->keep_alive(req_.keep_alive());
    res->body() = INDEX_HTML;
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

    if (req_.method() == http::verb::post && req_.target() == "/load") {
      handle_load();
      return;
    }

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
    auto body = render_admin_page(state_);
    auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
    res->set(http::field::server, "chat-admin");
    res->set(http::field::content_type, "text/html; charset=utf-8");
    res->keep_alive(req_.keep_alive());
    res->body() = std::move(body);
    res->prepare_payload();
    write_response(res);
  }

  void handle_load() {
    state_->update_last_script(req_.body());
    bool enable = req_.body().find("repeat_last_message_twice") != std::string::npos;
    state_->enable_repeat_last_message(enable);

    std::string message;
    if (enable) {
      message = "DLL обновление установлено: повтор последнего сообщения включен.";
    } else {
      message = "DLL загружена, но функция repeat_last_message_twice не найдена.";
    }

    auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
    res->set(http::field::server, "chat-admin");
    res->set(http::field::content_type, "text/plain; charset=utf-8");
    res->keep_alive(false);
    res->body() = std::move(message);
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

// ========= Listener =========
class Listener : public std::enable_shared_from_this<Listener> {
public:
  Listener(boost::asio::io_context& ioc, tcp::endpoint ep, std::shared_ptr<SharedState> st)
    : ioc_(ioc), acceptor_(ioc), state_(std::move(st)) {
    beast::error_code ec;

    acceptor_.open(ep.protocol(), ec);
    if (ec) {
      throw std::runtime_error("Listener open failed: " + ec.message());
    }

    // Разрешаем переиспользовать порт, чтобы избежать залипания в TIME_WAIT.
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec) {
      throw std::runtime_error("Listener reuse_address failed: " + ec.message());
    }

    acceptor_.bind(ep, ec);
    if (ec) {
      throw std::runtime_error("Listener bind failed: " + ec.message());
    }

    acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
      throw std::runtime_error("Listener listen failed: " + ec.message());
    }
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

class AdminListener : public std::enable_shared_from_this<AdminListener> {
public:
  AdminListener(boost::asio::io_context& ioc, tcp::endpoint ep, std::shared_ptr<SharedState> st)
    : ioc_(ioc), acceptor_(ioc), state_(std::move(st)) {
    beast::error_code ec;

    acceptor_.open(ep.protocol(), ec);
    if (ec) {
      throw std::runtime_error("AdminListener open failed: " + ec.message());
    }

    acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec) {
      throw std::runtime_error("AdminListener reuse_address failed: " + ec.message());
    }

    acceptor_.bind(ep, ec);
    if (ec) {
      throw std::runtime_error("AdminListener bind failed: " + ec.message());
    }

    acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
      throw std::runtime_error("AdminListener listen failed: " + ec.message());
    }
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
    std::cout << "Chat UI listening on port " << chat_port << ", admin panel on port " << admin_port << "\n";
    ioc.run();
  } catch (const std::exception& e) {
    std::cerr << "server_web error: " << e.what() << "\n";
    return 1;
  }
}
