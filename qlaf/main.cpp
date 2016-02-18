
#include <QtGui>

#include "window.h"
#include "initdbus.h"

int main(int argc, char *argv[])
{
    Q_INIT_RESOURCE(systray);

    QApplication app(argc, argv);
    QApplication::setQuitOnLastWindowClosed(false);

    Window window;
    window.setWindowIcon(QIcon(":/icons/laf_icon.svg"));
    window.setWindowTitle("qLAF - Linux Application Firewall");

    initDBus dbus;
    dbus.setup();

    QObject::connect(&dbus, SIGNAL(recvEvent(QString)), &window, SLOT(addEvent(QString)));

    return app.exec();
}
