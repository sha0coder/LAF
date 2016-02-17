#ifndef WINDOW_H
#define WINDOW_H

#include <QApplication>
#include <QMessageBox>
#include <QWidget>
#include <QMenu>
#include <QSystemTrayIcon>
#include <QComboBox>
#include <QCheckBox>
#include <QGroupBox>
#include <QSpinBox>
#include <QTextEdit>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QDebug>
#include <QFile>
#include <QProcess>

#include "common.h"

class Window : public QWidget
{
    Q_OBJECT
public:
    explicit Window(QWidget *parent = 0);
    ~Window();
    QSystemTrayIcon *trayIcon;

signals:

public slots:

private slots:
    void iconActivated(QSystemTrayIcon::ActivationReason);
    void messageClicked();
    void setStatus_on();
    void setStatus_off();
    void setStatus(int);
    void updateWhitelist();
    void showAbout();
    void updateIcon();
    void addWhitelist(int, QString);
    int  getStatus();

private:
    void createTrayIcon();
    void createActions();

    QAction *disableAction;
    QAction *enableAction;
    QAction *aboutAction;
    QAction *updateAction;
    QAction *quitAction;
    QMenu   *trayIconMenu;
};

#endif // WINDOW_H
