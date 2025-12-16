#include "ChatWindow.h"

#include <QComboBox>
#include <QTcpSocket>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QWidget>
#include <QLabel>
#include <QMessageBox>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QRegularExpression>

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

ChatWindow::ChatWindow(QTcpSocket* socket, const QString& ip, quint16 port, const QString& nick, QWidget* parent)
    : QMainWindow(parent), socket_(socket), net_(new QNetworkAccessManager(this)), ip_(ip), port_(port), nick_(nick) {

    // Socket ownership
    socket_->setParent(this);

    auto* root = new QWidget(this);
    auto* main = new QVBoxLayout(root);

    // Top info + DLL switcher
    auto* topRow = new QHBoxLayout();
    topRow->addWidget(new QLabel(QString("Connected: %1:%2 as %3").arg(ip_).arg(port_).arg(nick_), root));

    topRow->addStretch();

    dllCombo_ = new QComboBox(root);
    dllCombo_->setMinimumWidth(200);
    refreshDllBtn_ = new QPushButton("Refresh DLLs", root);
    activateDllBtn_ = new QPushButton("Activate", root);

    manualDllEdit_ = new QLineEdit(root);
    manualDllEdit_->setPlaceholderText("or type dll name (e.g. orange)");

    topRow->addWidget(dllCombo_);
    topRow->addWidget(refreshDllBtn_);
    topRow->addWidget(activateDllBtn_);
    topRow->addWidget(manualDllEdit_);

    main->addLayout(topRow);

    chatView_ = new QTextEdit(root);
    chatView_->setReadOnly(true);
    main->addWidget(chatView_, 1);

    auto* bottomRow = new QHBoxLayout();
    input_ = new QLineEdit(root);
    sendBtn_ = new QPushButton("Send", root);

    bottomRow->addWidget(input_, 1);
    bottomRow->addWidget(sendBtn_);
    main->addLayout(bottomRow);

    setCentralWidget(root);
    setWindowTitle("Chat");
    resize(900, 520);

    connect(sendBtn_, &QPushButton::clicked, this, &ChatWindow::onSendClicked);
    connect(input_, &QLineEdit::returnPressed, this, &ChatWindow::onSendClicked);

    connect(socket_, &QTcpSocket::readyRead, this, &ChatWindow::onReadyRead);
    connect(socket_, &QTcpSocket::disconnected, this, &ChatWindow::onDisconnected);

    connect(refreshDllBtn_, &QPushButton::clicked, this, &ChatWindow::onRefreshDllsClicked);
    connect(activateDllBtn_, &QPushButton::clicked, this, &ChatWindow::onActivateDllClicked);

    // стартово попробуем обновить список DLL
    onRefreshDllsClicked();
}

void ChatWindow::onSendClicked() {
    const QString msg = input_->text().trimmed();
    if (msg.isEmpty()) return;
    input_->clear();
    sendLine(msg);
}

void ChatWindow::sendLine(const QString& s) {
    if (!socket_ || socket_->state() != QAbstractSocket::ConnectedState) {
        QMessageBox::warning(this, "Disconnected", "Socket is not connected.");
        return;
    }
    socket_->write((s + "\n").toUtf8());
    socket_->flush();
}

QString ChatWindow::stripAnsi(const QString& s) const {
    // убираем ANSI escape sequences вида \x1B[ ... m
    static QRegularExpression re("\x1B\\[[0-9;]*m");
    QString out = s;
    out.remove(re);
    return out;
}

void ChatWindow::appendLineColored(const QString& rawLine) {
    const QString line = stripAnsi(rawLine);

    QTextCharFormat fmt;
    // Простая раскраска
    if (line.startsWith("SYS:")) {
        fmt.setFontItalic(true);
    } else if (line.startsWith("MSG:")) {
        fmt.setFontWeight(QFont::Normal);
    }

    // Выделим ник внутри "MSG: Nick: text"
    // Формат сервера у тебя: "MSG: Vilen: hello"
    QString nickPart;
    QString rest = line;

    if (line.startsWith("MSG:")) {
        // пытаемся вытащить ник
        const int firstColon = line.indexOf(':'); // после MSG
        const int secondColon = line.indexOf(':', firstColon + 1); // после Nick
        if (secondColon > 0) {
            // "MSG: " = 4 + возможный пробел
            // возьмем аккуратно: после "MSG:" и пробела
            QString afterPrefix = line.mid(4).trimmed(); // "Vilen: text"
            int nickEnd = afterPrefix.indexOf(':');
            if (nickEnd > 0) {
                nickPart = afterPrefix.left(nickEnd).trimmed();
                rest = "MSG: " + afterPrefix.mid(0); // оставим как есть
            }
        }
    }

    QTextCursor cur(chatView_->document());
    cur.movePosition(QTextCursor::End);

    // SYS — отдельный стиль
    if (line.startsWith("SYS:")) {
        QTextCharFormat f = fmt;
        cur.insertText(line + "\n", f);
        chatView_->setTextCursor(cur);
        return;
    }

    // MSG — выделим ник
    if (line.startsWith("MSG:") && !nickPart.isEmpty()) {
        // Вставим "MSG: "
        QTextCharFormat baseFmt;
        cur.insertText("MSG: ", baseFmt);

        QTextCharFormat nickFmt;
        nickFmt.setFontWeight(QFont::Bold);
        cur.insertText(nickPart, nickFmt);

        QTextCharFormat base2;
        // остаток после "Nick"
        QString afterPrefix = line.mid(4).trimmed(); // "Nick: text"
        int nickEnd = afterPrefix.indexOf(':');
        QString tail = afterPrefix.mid(nickEnd); // ": text"
        cur.insertText(tail + "\n", base2);

        chatView_->setTextCursor(cur);
        return;
    }

    // default
    cur.insertText(line + "\n", fmt);
    chatView_->setTextCursor(cur);
}

void ChatWindow::onReadyRead() {
    recvBuf_.append(socket_->readAll());

    // читаем по строкам
    while (true) {
        int idx = recvBuf_.indexOf('\n');
        if (idx < 0) break;
        QByteArray line = recvBuf_.left(idx);
        recvBuf_ = recvBuf_.mid(idx + 1);

        QString s = QString::fromUtf8(line);
        s = s.trimmed();
        if (!s.isEmpty())
            appendLineColored(s);
    }
}

void ChatWindow::onDisconnected() {
    appendLineColored("SYS: Disconnected.");
}

QString ChatWindow::baseNameNoExt(const QString& file) const {
    QString f = file.trimmed();
    if (f.endsWith(".dll")) f.chop(4);
    if (f.endsWith(".so"))  f.chop(3);
    if (f.endsWith(".dylib")) f.chop(6);
    return f;
}

void ChatWindow::onActivateDllClicked() {
    QString name = manualDllEdit_->text().trimmed();
    if (name.isEmpty()) {
        name = dllCombo_->currentText().trimmed();
    }
    if (name.isEmpty()) {
        QMessageBox::warning(this, "DLL", "Select or type DLL name.");
        return;
    }

    const QString base = baseNameNoExt(name);
    sendLine("call " + base);
    appendLineColored("SYS: Sent -> call " + base);
}

void ChatWindow::onRefreshDllsClicked() {
    // Мы предполагаем, что у админки есть JSON endpoint:
    // GET http://IP/list_dlls  -> {"files":["a.dll","b.dll"],"active":"orange.dll"}
    // Если у тебя другой путь — скажешь, я подгоню.
    QUrl url(QString("http://%1/list_dlls").arg(ip_));
    QNetworkRequest req(url);

    QNetworkReply* r = net_->get(req);
    connect(r, &QNetworkReply::finished, this, [this, r]() {
        const QByteArray data = r->readAll();
        const auto err = r->error();
        r->deleteLater();

        if (err != QNetworkReply::NoError) {
            // не ломаем UX: просто сообщаем и оставляем ручной ввод
            appendLineColored("SYS: DLL list fetch failed (no /list_dlls). Use manual field or dropdown if already filled.");
            return;
        }

        QJsonParseError pe{};
        QJsonDocument doc = QJsonDocument::fromJson(data, &pe);
        if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
            appendLineColored("SYS: DLL list response is not valid JSON.");
            return;
        }

        QJsonObject obj = doc.object();
        QJsonArray files = obj.value("files").toArray();

        dllCombo_->clear();
        for (const auto& v : files) {
            dllCombo_->addItem(v.toString());
        }

        const QString active = obj.value("active").toString();
        if (!active.isEmpty()) {
            int i = dllCombo_->findText(active);
            if (i >= 0) dllCombo_->setCurrentIndex(i);
            appendLineColored("SYS: Active DLL: " + active);
        } else {
            appendLineColored("SYS: DLL list updated.");
        }
    });
}
