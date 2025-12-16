#include "MainWindow.h"
#include "ChatWindow.h"

#include <QLineEdit>
#include <QPushButton>
#include <QFormLayout>
#include <QWidget>
#include <QMessageBox>
#include <QTcpSocket>
#include <QSettings>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    auto* root = new QWidget(this);
    auto* layout = new QFormLayout(root);

    ipEdit_ = new QLineEdit(root);
    portEdit_ = new QLineEdit(root);
    nickEdit_ = new QLineEdit(root);
    connectBtn_ = new QPushButton("Connect", root);

    layout->addRow("IP:", ipEdit_);
    layout->addRow("Port:", portEdit_);
    layout->addRow("Nick:", nickEdit_);
    layout->addRow(connectBtn_);

    setCentralWidget(root);
    setWindowTitle("Chat Client");
    resize(420, 170);

    loadSettings();

    connect(connectBtn_, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
}

void MainWindow::loadSettings() {
    QSettings s("Vilen", "ChatClient");
    ipEdit_->setText(s.value("ip", "127.0.0.1").toString());
    portEdit_->setText(s.value("port", "8080").toString());
    nickEdit_->setText(s.value("nick", "Vilen").toString());
}

void MainWindow::saveSettings() {
    QSettings s("Vilen", "ChatClient");
    s.setValue("ip", ipEdit_->text().trimmed());
    s.setValue("port", portEdit_->text().trimmed());
    s.setValue("nick", nickEdit_->text().trimmed());
}

void MainWindow::onConnectClicked() {
    const QString ip = ipEdit_->text().trimmed();
    const QString portStr = portEdit_->text().trimmed();
    const QString nick = nickEdit_->text().trimmed();

    bool ok = false;
    const quint16 port = portStr.toUShort(&ok);

    if (ip.isEmpty() || nick.isEmpty() || !ok || port == 0) {
        QMessageBox::warning(this, "Error", "Fill IP/Port/Nick correctly.");
        return;
    }

    saveSettings();

    auto* sock = new QTcpSocket(); // owner станет ChatWindow
    sock->connectToHost(ip, port);
    if (!sock->waitForConnected(3000)) {
        QMessageBox::critical(this, "Connect failed", sock->errorString());
        sock->deleteLater();
        return;
    }

    // Отправляем ник
    sock->write(("#me " + nick + "\n").toUtf8());
    sock->flush();

    // Переходим в окно чата
    auto* chat = new ChatWindow(sock, ip, port, nick);
    chat->setAttribute(Qt::WA_DeleteOnClose, true);
    chat->show();
    this->close();
}
