#pragma once

#include <boost/asio.hpp>

#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace chat {

using boost::asio::ip::tcp;

class ChatServer;

class ClientSession : public std::enable_shared_from_this<ClientSession> {
public:
    ClientSession(tcp::socket socket, ChatServer& server);

    tcp::socket& socket();

    std::string remote_ip() const;

    void start();
    void deliver(const std::string& line);

    std::string name;
    bool named = false;

private:
    void do_read();
    void on_read(const boost::system::error_code& ec, std::size_t);
    void do_write();

    tcp::socket socket_;
    boost::asio::streambuf buffer_;
    std::deque<std::string> outbox_;
    ChatServer& server_;
};

class ChatServer {
public:
    ChatServer(boost::asio::io_context& io, std::uint16_t port);

    void join(std::shared_ptr<ClientSession> s);
    void leave(std::shared_ptr<ClientSession> s);
    void on_line(std::shared_ptr<ClientSession> s, const std::string& raw);

    static std::string trim_after(const std::string& line, const std::string& cmd);

private:
    void do_accept();
    void broadcast_public(const std::string& from, const std::string& text);
    bool is_blocked(const std::string& receiver, const std::string& sender);
    void deliver_offline_inbox_if_any(std::shared_ptr<ClientSession> s);

    tcp::acceptor acceptor_;
    std::unordered_set<std::shared_ptr<ClientSession>> sessions_;

public:
    std::unordered_map<std::string, std::shared_ptr<ClientSession>> online;
    std::unordered_map<std::string, std::string> last_name_by_ip;
    std::unordered_map<std::string, std::unordered_set<std::string>> blacklist;
    std::unordered_map<std::string, std::unordered_set<std::string>> favorites;
    std::unordered_map<std::string, std::deque<std::pair<std::string, std::string>>> offline_inbox;
};

void run_server(std::uint16_t port);

}  // namespace chat

