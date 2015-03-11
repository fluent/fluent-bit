#-------------------------------------------------
#
# Project created by QtCreator 2013-07-14T12:43:55
#
#-------------------------------------------------

QT       += core gui

TARGET = 15qt
TEMPLATE = app

LIBS += -lxbeep -lxbee

SOURCES += main.cpp\
        window.cpp\
        xbeeqt.cpp

HEADERS  += window.h\
        xbeeqt.h

FORMS    += window.ui
