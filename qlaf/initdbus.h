#ifndef INITDBUS_H
#define INITDBUS_H

#include <QObject>
#include <QDebug>
#include <QDBusConnection>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QDate>

#include "common.h"

class initDBus : public QObject
{
    Q_OBJECT
public:
    explicit initDBus(QObject *parent = 0);
    void setup();
    QSystemTrayIcon *trayIcon;
    QTableWidget    *table;

signals:
    void recvEvent(QString);

public slots:
    void recvSlot(QString);

};

#endif // INITDBUS_H
