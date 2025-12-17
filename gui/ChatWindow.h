#pragma once
#include <QMainWindow>
#include <QString>

class QTcpSocket;
class QTextEdit;
class QLineEdit;
class QPushButton;
class QComboBox;
class QLabel;
class QListWidget;
class QTimer;
class QNetworkAccessManager;

class ChatWindow : public QMainWindow {
    Q_OBJECT
public:
    ChatWindow(QTcpSocket* socket, const QString& ip, quint16 port, const QString& nick, QWidget* parent = nullptr);

private slots:
    void onSendClicked();
    void onReadyRead();
    void onDisconnected();

    void onRefreshDllsClicked();
    void onActivateDllClicked();
    void requestOnlineUsers(bool showAnnouncement = false);

private:
    void appendLineColored(const QString& line);
    QString stripAnsi(const QString& s) const;
    void sendLine(const QString& s);

    QString baseNameNoExt(const QString& file) const;

    QTcpSocket* socket_{};
    QTextEdit* chatView_{};
    QLineEdit* input_{};
    QPushButton* sendBtn_{};
    QLabel* headerLabel_{};

    // DLL switcher
    QComboBox* dllCombo_{};
    QPushButton* refreshDllBtn_{};
    QPushButton* activateDllBtn_{};
    QLineEdit* manualDllEdit_{};

    // Online users
    QListWidget* onlineList_{};
    QPushButton* refreshUsersBtn_{};
    QTimer* whoTimer_{};
    bool showOnlineAnnouncementPending_ = false;

    QNetworkAccessManager* net_{};
    QString ip_;
    quint16 port_{};
    QString nick_;

    QByteArray recvBuf_;
};
