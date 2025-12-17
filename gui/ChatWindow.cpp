#include "ChatWindow.h"

#include <QAbstractSocket>
#include <QComboBox>
#include <QFrame>
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
#include <QColor>
#include <QGroupBox>
#include <QListWidget>
#include <QTimer>
#include <QAbstractItemView>
#include <optional>

#include <QDebug>

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
    root->setObjectName("chatRoot");
    root->setStyleSheet(R"(
        QWidget#chatRoot { background-color: #0b1021; }
        QFrame#card { background-color: #0f172a; border: 1px solid #1f2937; border-radius: 12px; }
        QGroupBox#groupCard { background-color: #0f172a; border: 1px solid #1f2937; border-radius: 12px; margin-top: 12px; }
        QGroupBox#groupCard::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #9ca3af; font-weight: 600; }
        QLabel#title { color: #e2e8f0; font-size: 20px; font-weight: 700; }
        QLabel#subtitle { color: #9ca3af; }
        QLabel#pill { background-color: #10b98133; color: #34d399; padding: 6px 10px; border-radius: 14px; font-weight: 600; }
        QTextEdit { background-color: #0b1220; color: #e5e7eb; border-radius: 10px; border: 1px solid #1f2937; font-family: "JetBrains Mono", monospace; }
        QListWidget { background-color: #0b1220; color: #e5e7eb; border-radius: 10px; border: 1px solid #1f2937; }
        QLineEdit { background-color: #0b1220; color: #e5e7eb; border-radius: 8px; border: 1px solid #1f2937; padding: 8px; }
        QPushButton { background-color: #2563eb; color: white; border: none; border-radius: 10px; padding: 10px 14px; font-weight: 600; }
        QPushButton:hover { background-color: #1d4ed8; }
        QPushButton#ghost { background-color: transparent; color: #9ca3af; border: 1px dashed #1f2937; }
    )");

    auto* main = new QVBoxLayout(root);
    main->setContentsMargins(16, 16, 16, 16);
    main->setSpacing(12);

    auto* header = new QFrame(root);
    header->setObjectName("card");
    auto* headerLayout = new QVBoxLayout(header);
    headerLabel_ = new QLabel(QString("Подключено к %1:%2").arg(ip_).arg(port_), header);
    headerLabel_->setObjectName("title");
    headerLayout->addWidget(headerLabel_);
    auto* sub = new QLabel(tr("Вы вошли как %1").arg(nick_), header);
    sub->setObjectName("subtitle");
    headerLayout->addWidget(sub);
    main->addWidget(header);

    auto* content = new QHBoxLayout();
    content->setSpacing(14);
    main->addLayout(content, 1);

    auto* chatCard = new QFrame(root);
    chatCard->setObjectName("card");
    auto* chatLayout = new QVBoxLayout(chatCard);

    auto* chatHeader = new QHBoxLayout();
    auto* chatTitle = new QLabel(tr("Комнаты и сообщения"), chatCard);
    chatTitle->setObjectName("subtitle");
    chatHeader->addWidget(chatTitle);
    chatHeader->addStretch();
    auto* livePill = new QLabel(tr("online"), chatCard);
    livePill->setObjectName("pill");
    chatHeader->addWidget(livePill);
    chatLayout->addLayout(chatHeader);

    chatView_ = new QTextEdit(chatCard);
    chatView_->setReadOnly(true);
    chatView_->setPlaceholderText(tr("Сообщения появятся здесь"));
    chatLayout->addWidget(chatView_, 1);

    auto* bottomRow = new QHBoxLayout();
    input_ = new QLineEdit(chatCard);
    input_->setPlaceholderText(tr("Напишите сообщение..."));
    sendBtn_ = new QPushButton(tr("Отправить"), chatCard);

    bottomRow->addWidget(input_, 1);
    bottomRow->addWidget(sendBtn_);
    chatLayout->addLayout(bottomRow);

    content->addWidget(chatCard, 2);

    auto* sideCard = new QFrame(root);
    sideCard->setObjectName("card");
    auto* sideLayout = new QVBoxLayout(sideCard);

    auto* dllBox = new QGroupBox(tr("Плагины DLL"), sideCard);
    dllBox->setObjectName("groupCard");
    auto* dllLayout = new QVBoxLayout(dllBox);
    dllCombo_ = new QComboBox(dllBox);
    dllCombo_->setMinimumWidth(220);
    dllCombo_->setPlaceholderText(tr("Выберите библиотеку"));
    refreshDllBtn_ = new QPushButton(tr("Обновить список"), dllBox);
    activateDllBtn_ = new QPushButton(tr("Активировать"), dllBox);
    manualDllEdit_ = new QLineEdit(dllBox);
    manualDllEdit_->setPlaceholderText(tr("или введите имя (например, orange)"));

    dllLayout->addWidget(dllCombo_);
    dllLayout->addWidget(manualDllEdit_);
    dllLayout->addWidget(refreshDllBtn_);
    dllLayout->addWidget(activateDllBtn_);
    sideLayout->addWidget(dllBox);

    auto* usersBox = new QGroupBox(tr("В сети сейчас"), sideCard);
    usersBox->setObjectName("groupCard");
    auto* usersLayout = new QVBoxLayout(usersBox);
    onlineList_ = new QListWidget(usersBox);
    onlineList_->setSelectionMode(QAbstractItemView::NoSelection);
    onlineList_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    refreshUsersBtn_ = new QPushButton(tr("Обновить список"), usersBox);
    usersLayout->addWidget(onlineList_, 1);
    usersLayout->addWidget(refreshUsersBtn_);
    sideLayout->addWidget(usersBox, 1);

    sideLayout->addStretch();
    content->addWidget(sideCard, 1);

    setCentralWidget(root);
    setWindowTitle("Chat Lounge");
    resize(1100, 640);

    connect(sendBtn_, &QPushButton::clicked, this, &ChatWindow::onSendClicked);
    connect(input_, &QLineEdit::returnPressed, this, &ChatWindow::onSendClicked);

    connect(socket_, &QTcpSocket::readyRead, this, &ChatWindow::onReadyRead);
    connect(socket_, &QTcpSocket::disconnected, this, &ChatWindow::onDisconnected);

    connect(refreshDllBtn_, &QPushButton::clicked, this, &ChatWindow::onRefreshDllsClicked);
    connect(activateDllBtn_, &QPushButton::clicked, this, &ChatWindow::onActivateDllClicked);
    connect(refreshUsersBtn_, &QPushButton::clicked, this, [this]() { requestOnlineUsers(true); });

    whoTimer_ = new QTimer(this);
    whoTimer_->setInterval(12000);
    connect(whoTimer_, &QTimer::timeout, this, [this]() { requestOnlineUsers(false); });
    whoTimer_->start();

    // стартово попробуем обновить список DLL
    onRefreshDllsClicked();
    requestOnlineUsers(false);
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


static std::optional<QColor> xterm256_to_qcolor(int idx) {
    if (idx < 0 || idx > 255) return std::nullopt;

    // 0–15: базовые (приблизительно)
    static const int base[16][3] = {
        {0,0,0},{128,0,0},{0,128,0},{128,128,0},{0,0,128},{128,0,128},{0,128,128},{192,192,192},
        {128,128,128},{255,0,0},{0,255,0},{255,255,0},{0,0,255},{255,0,255},{0,255,255},{255,255,255}
    };
    if (idx < 16) return QColor(base[idx][0], base[idx][1], base[idx][2]);

    // 16–231: 6x6x6 color cube
    if (idx >= 16 && idx <= 231) {
        int c = idx - 16;
        int r = c / 36;
        int g = (c / 6) % 6;
        int b = c % 6;
        auto conv = [](int v) { return v == 0 ? 0 : 55 + v * 40; };
        return QColor(conv(r), conv(g), conv(b));
    }

    // 232–255: grayscale
    int level = 8 + (idx - 232) * 10;
    return QColor(level, level, level);
}

static void apply_sgr_to_format(const QString& sgr, QTextCharFormat& fmt) {
    // sgr = "38;5;214" или "31" и т.д.
    const auto parts = sgr.split(';', Qt::SkipEmptyParts);

    for (int i = 0; i < parts.size(); ++i) {
        bool ok = false;
        int code = parts[i].toInt(&ok);
        if (!ok) continue;

        if (code == 0) { // reset
            fmt = QTextCharFormat{};
        } else if (code == 1) { // bold
            fmt.setFontWeight(QFont::Bold);
        } else if (code == 3) { // italic
            fmt.setFontItalic(true);
        } else if (code >= 30 && code <= 37) { // basic fg
            static const int ansi[8][3] = {
                {0,0,0},{128,0,0},{0,128,0},{128,128,0},{0,0,128},{128,0,128},{0,128,128},{192,192,192}
            };
            int k = code - 30;
            fmt.setForeground(QColor(ansi[k][0], ansi[k][1], ansi[k][2]));
        } else if (code == 39) { // default fg
            fmt.clearForeground();
        } else if (code == 38) {
            // extended fg: 38;5;N  (мы поддержим только 256-color)
            if (i + 2 < parts.size() && parts[i+1] == "5") {
                bool ok2 = false;
                int idx = parts[i+2].toInt(&ok2);
                if (ok2) {
                    auto c = xterm256_to_qcolor(idx);
                    if (c) fmt.setForeground(*c);
                }
                i += 2;
            }
        }
    }
}

static QString strip_ansi(const QString& s) {
    static QRegularExpression re("\x1B\\[[0-9;]*m");
    QString out = s;
    out.remove(re);
    return out;
}
static std::optional<QColor> detectAnsiFgColor(const QString& s) {
    // 256-color: ESC[38;5;N m
    static QRegularExpression re256("\x1B\\[38;5;([0-9]{1,3})m");
    auto m = re256.match(s);
    if (m.hasMatch()) {
        bool ok=false;
        int idx = m.captured(1).toInt(&ok);
        if (ok) return xterm256_to_qcolor(idx);
    }

    // basic: ESC[3Xm
    static QRegularExpression reBasic("\x1B\\[(3[0-7])m");
    m = reBasic.match(s);
    if (m.hasMatch()) {
        int code = m.captured(1).toInt();
        static const int ansi[8][3] = {
            {0,0,0},{128,0,0},{0,128,0},{128,128,0},{0,0,128},{128,0,128},{0,128,128},{192,192,192}
        };
        int k = code - 30;
        return QColor(ansi[k][0], ansi[k][1], ansi[k][2]);
    }

    return std::nullopt;
}


void ChatWindow::appendLineColored(const QString& rawLine) {
    QTextCursor cur(chatView_->document());
    cur.movePosition(QTextCursor::End);

    // 1. Определяем цвет из ANSI (если есть)
    QTextCharFormat textFmt;
    if (auto c = detectAnsiFgColor(rawLine)) {
        textFmt.setForeground(*c);
    }

    // 2. Убираем ANSI
    const QString line = strip_ansi(rawLine);

    if (line.startsWith("SYS: Online:")) {
        QString usersPart = line.mid(QString("SYS: Online:").size()).trimmed();
        onlineList_->clear();
        if (usersPart.isEmpty()) {
            onlineList_->addItem(tr("Сейчас никого нет в сети"));
        } else {
            for (const QString& name : usersPart.split(',', Qt::SkipEmptyParts)) {
                onlineList_->addItem(name.trimmed());
            }
        }

        if (!showOnlineAnnouncementPending_) {
            return;
        }
        showOnlineAnnouncementPending_ = false;
    }

    // ---- SYS ----
    if (line.startsWith("SYS:")) {
        QTextCharFormat f;
        f.setFontItalic(true);
        cur.insertText(line + "\n", f);
        chatView_->setTextCursor(cur);
        return;
    }

    // ---- MSG / FAV ----
    if (line.startsWith("MSG:") || line.startsWith("FAV:")) {
        const bool isFav = line.startsWith("FAV:");
        const int prefixLen = isFav ? 4 : 4; // "MSG:" / "FAV:"

        // ищем "Nick: "
        int colon = line.indexOf(':', prefixLen);
        if (colon > 0) {
            QString prefix = line.left(prefixLen + 1);          // "MSG: "
            QString nick = line.mid(prefixLen + 1, colon - prefixLen); // "Vilen1"
            QString text = line.mid(colon + 1).trimmed();        // "hi"

            // prefix
            QTextCharFormat baseFmt;
            cur.insertText(prefix, baseFmt);

            // nick
            QTextCharFormat nickFmt;
            nickFmt.setFontWeight(QFont::Bold);
            cur.insertText(nick, nickFmt);

            // ": "
            cur.insertText(": ", baseFmt);

            // message text (цвет из DLL)
            cur.insertText(text, textFmt);
            cur.insertText("\n");

            chatView_->setTextCursor(cur);
            return;
        }
    }

    // ---- fallback ----
    cur.insertText(line + "\n");
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
    if (whoTimer_) {
        whoTimer_->stop();
    }
    if (headerLabel_) {
        headerLabel_->setText(tr("Отключено от %1:%2").arg(ip_).arg(port_));
    }
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

void ChatWindow::requestOnlineUsers(bool showAnnouncement) {
    if (!socket_ || socket_->state() != QAbstractSocket::ConnectedState) {
        return;
    }
    showOnlineAnnouncementPending_ = showOnlineAnnouncementPending_ || showAnnouncement;
    sendLine("#who");
}

void ChatWindow::onRefreshDllsClicked() {
    // Мы предполагаем, что у админки есть JSON endpoint:
    // GET http://IP/list_dlls  -> {"files":["a.dll","b.dll"],"active":"orange.dll"}
    // Если у тебя другой путь — скажешь, я подгоню.
    QUrl url(QString("http://%1:80/list_files").arg(ip_));
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
        QJsonDocument doc = QJsonDocument::fromJson(data);
        dllCombo_->clear();

        if (doc.isArray()) {
            // ✅ формат админки: ["a.dll","b.dll"]
            QJsonArray arr = doc.array();
            for (const auto& v : arr) {
                dllCombo_->addItem(v.toString());
            }
            appendLineColored("SYS: DLL list updated.");
            return;
        }

        if (doc.isObject()) {
            // 🔁 на будущее, если сделаешь расширенный API
            QJsonObject obj = doc.object();
            QJsonArray files = obj.value("files").toArray();
            for (const auto& v : files) {
                dllCombo_->addItem(v.toString());
            }

            QString active = obj.value("active").toString();
            if (!active.isEmpty()) {
                int i = dllCombo_->findText(active);
                if (i >= 0) dllCombo_->setCurrentIndex(i);
                appendLineColored("SYS: Active DLL: " + active);
            } else {
                appendLineColored("SYS: DLL list updated.");
            }
            return;
        }

        appendLineColored("SYS: DLL list response has unknown format.");
    });
}
