#include "window.h"

Window::Window(QWidget *parent) :
    QWidget(parent)
{
    createActions();
    createTrayIcon();

    connect(trayIcon, SIGNAL(messageClicked()), this, SLOT(messageClicked()));
    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
              this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));

    updateIcon();
    trayIcon->show();

    qDebug() << "Program started!";
}

Window::~Window()
{
}

void Window::setStatus_on() {
    setStatus(1);
}

void Window::setStatus_off() {
    setStatus(0);
}

void Window::setStatus(int status) {

    QString program = "pkexec";
    QStringList arguments;
    QProcess *myProcess = new QProcess(this);

    arguments << "lafctl";
    if (status)
        arguments << "-d";
    else
        arguments << "-e";

    myProcess->start(program, arguments);
    connect(myProcess, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(updateIcon()));
}

void Window::showAbout()
{
    QMessageBox::about(this, "qLAF", "<h1>qLAF</i> <small>" VERSION "</small></h1><h3 align=center></h3><p>LAF (Linux Application Firewall) is a kernel driver that blocks network sockets, allowing only whitelisted process to connect to the LAN and the Internet. This project is licensed under the <a href='http://www.gnu.org/licenses/gpl-3.0.html'>GPLv3</a> license.<br>More information in the <a href='https://github.com/sha0coder/LAF'>project page</a>.</p><p>2015-2016 (c) @sha0coder and @capi_x</p>");
}

void Window::updateIcon()
{
    if (getStatus())
        trayIcon->setIcon(QIcon(":/icons/laf_green.svg"));
    else
        trayIcon->setIcon(QIcon(":/icons/laf_red.svg"));
}

int Window::getStatus()
{
    int ret = 0;

    QFile file("/proc/sys/kernel/laf/enabled");
    if(!file.open(QIODevice::ReadOnly)) {
        QMessageBox::information(0, "error", file.errorString());
    }
    QTextStream in(&file);

    ret = in.read(1).toInt();

    file.close();

    return ret;
}

void Window::updateWhitelist()
{
    QString program = "pkexec";
    QStringList arguments;
    QProcess *myProcess = new QProcess(this);

    arguments << "lafctl" << "-u";
    myProcess->start(program, arguments);

    connect(myProcess, SIGNAL(finished(int, QProcess::ExitStatus)), this, SLOT(updateWhitelist_slot()));
}

void Window::createActions()
{
    disableAction = new QAction(tr("&Disable LAF"), this);
    connect(disableAction, SIGNAL(triggered()), this, SLOT(setStatus_on()));

    enableAction = new QAction(tr("&Enable LAF"), this);
    connect(enableAction, SIGNAL(triggered()), this, SLOT(setStatus_off()));

    updateAction = new QAction(tr("&Update whitelist"), this);
    connect(updateAction, SIGNAL(triggered()), this, SLOT(updateWhitelist()));

    aboutAction = new QAction(tr("&About"), this);
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(showAbout()));

    quitAction = new QAction(tr("&Quit"), this);
    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
}

void Window::createTrayIcon()
{
    trayIconMenu = new QMenu(this);

    trayIconMenu->addAction(disableAction);
    trayIconMenu->addAction(enableAction);
    trayIconMenu->addAction(updateAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(aboutAction);
    trayIconMenu->addAction(quitAction);

    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setContextMenu(trayIconMenu);
}

void Window::messageClicked()
{
    int     pid = trayIcon->objectName().split('/')[0].toInt();
    int     tid = trayIcon->objectName().split('/')[1].toInt();
    QString cmd = trayIcon->objectName().split('/')[2];

    QString text = QString(tr("Do you want add \"%1\" to the whitelist?").arg(cmd));
    int ret = QMessageBox::question(0, tr("Add program to the whitelist"), text, QMessageBox::Yes, QMessageBox::No);

    if(ret == QMessageBox::Yes) {
        if (pid == tid)
            addWhitelist(0,cmd);
        else
            addWhitelist(1,cmd);
    }
}

void Window::addWhitelist(int similar, QString cmd)
{
    QString program = "pkexec";
    QStringList arguments;
    QProcess *myProcess = new QProcess(this);

    if (similar)
        arguments << "lafctl" << "-f" << "/tmp/laf.cfg" << "-a" << "1" << cmd;
    else
        arguments << "lafctl" << "-f" << "/tmp/laf.cfg" << "-a" << "0" << cmd;

    myProcess->start(program, arguments);
}

void Window::iconActivated(QSystemTrayIcon::ActivationReason reason)
{

    switch (reason) {
//    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
        if (this->isVisible())
            this->hide();
        else
            this->show();

        break;
    case QSystemTrayIcon::MiddleClick:
            updateIcon();
        break;
    default:
        ;
    }

}
