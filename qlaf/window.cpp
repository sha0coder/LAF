#include "window.h"

Window::Window(QWidget *parent) :
    QWidget(parent)
{
    // Tray unmuted by default
    trayMuted = 0;

    createActions();
    createTrayIcon();

    connect(trayIcon, SIGNAL(messageClicked()), this, SLOT(messageClicked()));
    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
              this, SLOT(iconActivated(QSystemTrayIcon::ActivationReason)));

    updateIcon();
    trayIcon->show();

    QVBoxLayout *layout  = new QVBoxLayout(this);
    QToolBar    *toolbar = new QToolBar;
    QLabel      *label   = new QLabel;

    table = new QTableWidget(0,8);
    table->setColumnWidth(0,160);
    table->setColumnWidth(1,60);
    table->setColumnWidth(2,60);
    table->setColumnWidth(3,180);
    table->setColumnWidth(4,60);
    table->setColumnWidth(5,60);
    table->setColumnWidth(6,180);
    table->setColumnWidth(7,60);

    label->setText(tr("Event Log"));
    this->resize(900,500);

    layout->addWidget(toolbar);
    layout->addWidget(label);
    layout->addWidget(table);

    QStringList header;
    header << tr("Date") << tr("Family") << tr("Protocol") << tr("Command") << "PID" << "TID" << tr("Parent") << "PPID";
    table->setHorizontalHeaderLabels(header);

    qDebug() << "Program started!";
}

Window::~Window()
{
}

void Window::addEvent(QString event)
{
    QString fam   = event.split('/')[1];
    QString proto = event.split('/')[2];
    QString cmd   = event.split('/')[3];
    QString pid   = event.split('/')[4];
    QString tid   = event.split('/')[5];
    QString pcmd  = event.split('/')[6];
    QString ppid  = event.split('/')[7];

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

    trayIcon->setObjectName(pid + "/" + tid + "/" + cmd);
    if (!trayMuted)
        trayIcon->showMessage("Application networking blocked", text, QSystemTrayIcon::Warning, LAF_MSG_TIMEOUT * 1000);

    // Amber icon until timeout
    setIcon(2);
    QTimer::singleShot(LAF_MSG_TIMEOUT * 1000, this, SLOT(updateIcon()));

    table->insertRow(0);
    for (int rc = 0; rc < 8; rc++) {
        table->setItem(0,rc,new QTableWidgetItem());
        table->item(0,rc)->setFlags(Qt::ItemIsEnabled);
    }

    table->item(0,0)->setText(QTime::currentTime().toString() + " " + QDate::currentDate().toString(Qt::ISODate));
    table->item(0,1)->setText(fam);
    table->item(0,2)->setText(proto);
    table->item(0,3)->setText(cmd);
    table->item(0,4)->setText(pid);
    table->item(0,5)->setText(tid);
    table->item(0,6)->setText(pcmd);
    table->item(0,7)->setText(ppid);

    connect(table, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(addItemWhitelist(int, int)),Qt::UniqueConnection);
}

void Window::setStatus_on() {
    setStatus(1);
}

void Window::setStatus_off() {
    setStatus(0);
}

void Window::setMute_on() {
//  trayIcon->showMessage("LAF", "Notifications muted",   QSystemTrayIcon::Information, LAF_MSG_TIMEOUT * 100);
    trayMuted = 1;
    updateIcon();
    muteAction->setEnabled(0);
    unmuteAction->setEnabled(1);
}

void Window::setMute_off() {
//  trayIcon->showMessage("LAF", "Notifications unmuted", QSystemTrayIcon::Information, LAF_MSG_TIMEOUT * 100);
    trayMuted = 0;
    updateIcon();
    muteAction->setEnabled(1);
    unmuteAction->setEnabled(0);
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
    setIcon(getStatus());
}

void Window::setIcon(int iconNum)
{
    switch (iconNum)
    {
        case 0:
            if (trayMuted)
                trayIcon->setIcon(QIcon(":/icons/laf_mute_red.svg"));
            else
                trayIcon->setIcon(QIcon(":/icons/laf_red.svg"));

            enableAction->setEnabled(1);
            disableAction->setEnabled(0);

            break;
        case 2:
            if (trayMuted)
                trayIcon->setIcon(QIcon(":/icons/laf_mute_amber.svg"));
            else
                trayIcon->setIcon(QIcon(":/icons/laf_amber.svg"));
            break;
        case 1:
        default:
            if (trayMuted)
                trayIcon->setIcon(QIcon(":/icons/laf_mute_green.svg"));
            else
                trayIcon->setIcon(QIcon(":/icons/laf_green.svg"));

            enableAction->setEnabled(0);
            disableAction->setEnabled(1);
            break;
    }
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
    enableAction  = new QAction(tr("&Enable LAF"), this);
    connect(enableAction, SIGNAL(triggered()), this, SLOT(setStatus_off()));

    disableAction = new QAction(tr("&Disable LAF"), this);
    connect(disableAction, SIGNAL(triggered()), this, SLOT(setStatus_on()));

    muteAction = new QAction(tr("&Mute LAF"), this);
    connect(muteAction, SIGNAL(triggered()), this, SLOT(setMute_on()));

    unmuteAction  = new QAction(tr("U&nmute LAF"), this);
    connect(unmuteAction, SIGNAL(triggered()), this, SLOT(setMute_off()));

    updateAction  = new QAction(tr("&Update whitelist"), this);
    connect(updateAction, SIGNAL(triggered()), this, SLOT(updateWhitelist()));

    aboutAction   = new QAction(tr("&About"), this);
    connect(aboutAction,  SIGNAL(triggered()), this, SLOT(showAbout()));

    quitAction    = new QAction(tr("&Quit"), this);
    connect(quitAction,   SIGNAL(triggered()), qApp, SLOT(quit()));
}

void Window::createTrayIcon()
{
    trayIconMenu = new QMenu(this);

    trayIconMenu->addAction(enableAction);
    trayIconMenu->addAction(disableAction);
    trayIconMenu->addSeparator();

    trayIconMenu->addAction(muteAction);
    trayIconMenu->addAction(unmuteAction);
    unmuteAction->setEnabled(0);
    trayIconMenu->addSeparator();

    trayIconMenu->addAction(updateAction);
    trayIconMenu->addSeparator();

    trayIconMenu->addAction(aboutAction);
    trayIconMenu->addAction(quitAction);

    trayIcon = new QSystemTrayIcon(this);
    trayIcon->setContextMenu(trayIconMenu);
}

void Window::messageClicked()
{
    if (trayIcon->objectName().length() == 0)
        return;

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

void Window::addItemWhitelist(int x, int y)
{
    int     pid = table->item(x, 4)->text().toInt();
    int     tid = table->item(x, 5)->text().toInt();
    QString cmd = table->item(x, 3)->text();
	UNUSED(y);

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
        arguments << "lafctl" << "-a" << "1" << cmd << "-u";
    else
        arguments << "lafctl" << "-a" << "0" << cmd << "-u";

    myProcess->start(program, arguments);
}

void Window::iconActivated(QSystemTrayIcon::ActivationReason reason)
{

    switch (reason) {
    case QSystemTrayIcon::Trigger:
//    case QSystemTrayIcon::DoubleClick:
        if (this->isVisible())
            this->hide();
        else
            this->show();

        break;
    case QSystemTrayIcon::MiddleClick:
            if (trayMuted)
                setMute_off();
            else
                setMute_on();
        break;
    default:
        break;
    }

}
