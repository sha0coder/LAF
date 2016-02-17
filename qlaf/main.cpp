
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

    initDBus dbus;
    dbus.setup();
    dbus.trayIcon = window.trayIcon;

    return app.exec();
}
