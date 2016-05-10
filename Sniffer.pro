#-------------------------------------------------
#
# Project created by QtCreator 2016-05-08T13:15:25
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Sniffer
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    sniffer-utils/sniffer.cpp

HEADERS  += mainwindow.h \
    sniffer-utils/sniffer.h \
    sniffer-utils/protocol_codes.h

FORMS    += mainwindow.ui

LIBS += -lpcap
