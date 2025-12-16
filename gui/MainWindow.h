#pragma once
#include <QMainWindow>

class QLineEdit;
class QPushButton;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onConnectClicked();

private:
    void loadSettings();
    void saveSettings();

    QLineEdit* ipEdit_{};
    QLineEdit* portEdit_{};
    QLineEdit* nickEdit_{};
    QPushButton* connectBtn_{};
};
