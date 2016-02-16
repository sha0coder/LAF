QT += core gui dbus

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = qlaf
TEMPLATE = app


SOURCES += \
    main.cpp \
    window.cpp \
    initdbus.cpp

HEADERS += \
    window.h \
    initdbus.h \
    common.h

RESOURCES += \
    systray.qrc

FORMS +=
