#ifndef INITDBUS_H
#define INITDBUS_H

#include <QObject>
#include <QDebug>
#include <QDBusConnection>
#include <QSystemTrayIcon>

#include "common.h"

class initDBus : public QObject
{
    Q_OBJECT
public:
    explicit initDBus(QObject *parent = 0);
    void setup();
    QSystemTrayIcon *trayIcon;

signals:

public slots:
    void MySlot(QString);

};

#endif // INITDBUS_H
