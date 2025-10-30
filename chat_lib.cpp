#include "chat_lib.hpp"

#include <iostream>

namespace chat {

ClientSession::ClientSession(tcp::socket socket, ChatServer& server)
    : socket_(std::move(socket)), server_(server) {}

tcp::socket& ClientSession::socket() { return socket_; }

std::string ClientSession::remote_ip() const {
    try {
        return socket_.remote_endpoint().address().to_string();
    } catch (...) {
        return "unknown";
    }
}

void ClientSession::start() {
    do_read();
}

void ClientSession::deliver(const std::string& line) {
    bool writing = !outbox_.empty();
    outbox_.push_back(line);
    if (!writing) do_write();
}

void ClientSession::do_read() {
    auto self = shared_from_this();
    boost::asio::async_read_until(socket_, buffer_, '\n',
        [this, self](const boost::system::error_code& ec, std::size_t bytes) {
            on_read(ec, bytes);
        });
}

void ClientSession::on_read(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        server_.leave(shared_from_this());
        return;
    }
    std::istream is(&buffer_);
    std::string line;
    std::getline(is, line);
    server_.on_line(shared_from_this(), line);
    do_read();
}

void ClientSession::do_write() {
    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(outbox_.front()),
        [this, self](const boost::system::error_code& ec, std::size_t) {
            if (!ec) {
                outbox_.pop_front();
                if (!outbox_.empty()) do_write();
            } else {
                server_.leave(shared_from_this());
            }
        });
}

ChatServer::ChatServer(boost::asio::io_context& io, std::uint16_t port)
    : acceptor_(io, tcp::endpoint(tcp::v4(), port)) {
    do_accept();
}

void ChatServer::join(std::shared_ptr<ClientSession> s) {
    auto ip = s->remote_ip();
    if (auto it = last_name_by_ip.find(ip); it != last_name_by_ip.end()) {
        s->deliver("SYS: Обнаружен прежний IP. Использовать прежнее имя \"" + it->second + "\"? Команда: #me " + it->second + "\n");
    } else {
        s->deliver("SYS: Введите имя: #me <name>\n");
    }
    sessions_.insert(s);
}

void ChatServer::leave(std::shared_ptr<ClientSession> s) {
    sessions_.erase(s);
    if (!s->name.empty()) {
        online.erase(s->name);
    }
}

void ChatServer::on_line(std::shared_ptr<ClientSession> s, const std::string& raw) {
    std::string line = raw;
    while (!line.empty() && (line.back()=='\n' || line.back()=='\r')) line.pop_back();

    if (line.rfind("#me", 0) == 0) {
        std::string newname = trim_after(line, "#me");
        if (newname.empty()) { s->deliver("SYS: формат: #me <name>\n"); return; }
        if (online.count(newname) && online[newname] != s) {
            s->deliver("SYS: имя занято\n");
            return;
        }
        if (!s->name.empty()) online.erase(s->name);

        s->name  = newname;
        s->named = true;
        online[s->name] = s;
        last_name_by_ip[s->remote_ip()] = s->name;

        s->deliver("SYS: имя установлено: " + s->name + "\n");
        deliver_offline_inbox_if_any(s);
        return;
    }

    if (!s->named) { s->deliver("SYS: сначала укажите имя: #me <name>\n"); return; }

    if (line == "#help") {
        s->deliver(
            "SYS: Команды: #help, #who, #me <name>, #block <user>, #unblock <user>, "
            "#fav <user>, #unfav <user>, #massdm <text>\n"
            "SYS: ЛС: @user <text>\n"
        );
        return;
    }

    if (line == "#who") {
        std::string out = "SYS: Online: ";
        bool first = true;
        for (auto& [n, _] : online) {
            if (!first) out += ", ";
            out += n; first = false;
        }
        out += "\n";
        s->deliver(out);
        return;
    }

    if (line.rfind("#block", 0) == 0) {
        std::string who = trim_after(line, "#block");
        if (who.empty() || who == s->name) { s->deliver("SYS: #block <user>\n"); return; }
        blacklist[s->name].insert(who);
        s->deliver("SYS: добавлен в ЧС: " + who + "\n");
        return;
    }
    if (line.rfind("#unblock", 0) == 0) {
        std::string who = trim_after(line, "#unblock");
        if (who.empty()) { s->deliver("SYS: #unblock <user>\n"); return; }
        if (blacklist[s->name].erase(who)) s->deliver("SYS: удалён из ЧС: " + who + "\n");
        else s->deliver("SYS: не был в ЧС: " + who + "\n");
        return;
    }

    if (line.rfind("#fav", 0) == 0) {
        std::string who = trim_after(line, "#fav");
        if (who.empty() || who == s->name) { s->deliver("SYS: #fav <user>\n"); return; }
        favorites[s->name].insert(who);
        s->deliver("SYS: добавлен в любимые: " + who + "\n");
        return;
    }
    if (line.rfind("#unfav", 0) == 0) {
        std::string who = trim_after(line, "#unfav");
        if (who.empty()) { s->deliver("SYS: #unfav <user>\n"); return; }
        if (favorites[s->name].erase(who)) s->deliver("SYS: удалён из любимых: " + who + "\n");
        else s->deliver("SYS: не был в любимых: " + who + "\n");
        return;
    }

    if (line.rfind("#massdm", 0) == 0) {
        std::string text = trim_after(line, "#massdm");
        if (text.empty()) { s->deliver("SYS: #massdm <text>\n"); return; }
        for (auto& [name, sess] : online) {
            if (sess == s) continue;
            if (is_blocked(sess->name, s->name)) continue;
            sess->deliver("DM: от " + s->name + ": " + text + "\n");
        }
        return;
    }

    if (line.rfind("@", 0) == 0) {
        auto sp = line.find(' ');
        std::string to = (sp == std::string::npos) ? line.substr(1) : line.substr(1, sp-1);
        std::string text = (sp == std::string::npos) ? "" : line.substr(sp+1);
        if (to.empty() || text.empty()) { s->deliver("SYS: формат ЛС: @user <text>\n"); return; }

        if (online.count(to)) {
            auto recip = online[to];
            if (!is_blocked(recip->name, s->name)) {
                recip->deliver("DM: от " + s->name + ": " + text + "\n");
            }
            return;
        }
        auto& box = offline_inbox[to];
        if (box.size() >= 10) {
            s->deliver("SYS: ящик пользователя переполнен\n");
        } else {
            box.emplace_back(s->name, text);
            s->deliver("SYS: сообщение сохранено в офлайн-ящике для " + to + "\n");
        }
        return;
    }

    broadcast_public(s->name, line);
}

std::string ChatServer::trim_after(const std::string& line, const std::string& cmd) {
    if (line.size() <= cmd.size()) return "";
    std::string rest = line.substr(cmd.size());
    std::size_t p = rest.find_first_not_of(" \t");
    if (p == std::string::npos) return "";
    return rest.substr(p);
}

void ChatServer::do_accept() {
    acceptor_.async_accept(
        [this](const boost::system::error_code& ec, tcp::socket socket) {
            if (!ec) {
                auto session = std::make_shared<ClientSession>(std::move(socket), *this);
                join(session);
                session->start();
            }
            do_accept();
        });
}

void ChatServer::broadcast_public(const std::string& from, const std::string& text) {
    for (auto& [name, sess] : online) {
        if (is_blocked(name, from)) continue;
        bool fav = favorites[name].count(from) > 0;
        if (fav) sess->deliver("FAV: " + from + ": " + text + "\n");
        else     sess->deliver("MSG: " + from + ": " + text + "\n");
    }
}

bool ChatServer::is_blocked(const std::string& receiver, const std::string& sender) {
    auto it = blacklist.find(receiver);
    if (it == blacklist.end()) return false;
    return it->second.count(sender) > 0;
}

void ChatServer::deliver_offline_inbox_if_any(std::shared_ptr<ClientSession> s) {
    auto it = offline_inbox.find(s->name);
    if (it == offline_inbox.end()) return;
    for (auto& m : it->second) {
        if (!is_blocked(s->name, m.first)) {
            s->deliver("DM: (офлайн) от " + m.first + ": " + m.second + "\n");
        }
    }
    offline_inbox.erase(it);
}

void run_server(std::uint16_t port) {
    boost::asio::io_context io;
    ChatServer server(io, port);
    std::cout << "Server listening on port " << port << std::endl;
    io.run();
}

}  // namespace chat

