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

    bool conn = bus.connect("laf.signal.source","/laf/signal/alert","laf.signal.source","event",this,SLOT(MySlot(QString)));

    if (!conn) qDebug() << "conn: not connected";
}

void initDBus::MySlot(QString kk)
{
    QString fam   = kk.split('/')[1];
    QString proto = kk.split('/')[2];
    QString cmd   = kk.split('/')[3];
    QString pid   = kk.split('/')[4];
    QString tid   = kk.split('/')[5];
    QString pcmd  = kk.split('/')[6];
    QString ppid  = kk.split('/')[7];

    QString text;
    text.append("FAM: ");
    text.append(fam);
    text.append(" PROTO: ");
    text.append(proto);
    text.append(" CMD: ");
    text.append(cmd);
    text.append(" (");
    text.append(pid);
    text.append(") PCMD: ");
    text.append(pcmd);
    text.append(" (");
    text.append(ppid);
    text.append(")");

    trayIcon->showMessage("Application networking blocked", text, QSystemTrayIcon::Warning, LAF_MSG_TIMEOUT * 1000);
}
