#pragma once
#include <QMainWindow>
#include <QString>

class QTcpSocket;
class QTextEdit;
class QLineEdit;
class QPushButton;
class QComboBox;
class QNetworkAccessManager;
class QTimer;

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

private:
    void appendLineColored(const QString& line);
    QString stripAnsi(const QString& s) const;
    void sendLine(const QString& s);

    QString baseNameNoExt(const QString& file) const;

    QTcpSocket* socket_{};
    QTextEdit* chatView_{};
    QLineEdit* input_{};
    QPushButton* sendBtn_{};

    // DLL switcher
    QComboBox* dllCombo_{};
    QPushButton* refreshDllBtn_{};
    QPushButton* activateDllBtn_{};
    QLineEdit* manualDllEdit_{};

    QNetworkAccessManager* net_{};
    QString ip_;
    quint16 port_{};
    QString nick_;

    QByteArray recvBuf_;
};
