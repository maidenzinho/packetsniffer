QT += core gui widgets network

CONFIG += c++11

SOURCES += src/main.cpp \
           src/PacketSniffer.cpp \
           src/MainWindow.cpp

HEADERS += src/PacketSniffer.h \
           src/MainWindow.h

unix: LIBS += -lpcap
win32: LIBS += -lwpcap

INCLUDEPATH += /usr/include/pcap