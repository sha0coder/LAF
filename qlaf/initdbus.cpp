#include "initdbus.h"

initDBus::initDBus(QObject *parent) :
    QObject(parent)
{
}

void initDBus::setup()
{
    //signal sender=:1.68 -> dest=(null destination) serial=10 path=/laf/signal/alert; interface=laf.signal.source; member=event
    //   string "/2/0/kk/5710/5710/bash/1438"

    QDBusConnection bus = QDBusConnection::systemBus();

    if (bus.isConnected())
        qDebug() << "bus: connected";
    else
        fprintf(stderr, "Cannot connect to the D-Bus session bus.\n"
                        "To start it, run:\n"
                        "\teval `dbus-launch --auto-syntax`\n");

    bool conn = bus.connect("laf.signal.source","/laf/signal/alert","laf.signal.source","event",this,SLOT(recvSlot(QString)));

    if (!conn) qDebug() << "conn: not connected";
}

void initDBus::recvSlot(QString event)
{
    emit recvEvent(event);
}
