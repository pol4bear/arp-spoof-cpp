TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -pthread

LIBS += -lpcap
LIBS += -lnet
LIBS += -pthread

SOURCES += \
        arpspoofer.cpp \
        network/l3/arppacket.cpp \
        network/l3/icmppacket.cpp \
        network/l3/ippacket.cpp \
        network/l4/tcppacket.cpp \
        network/l4/udppacket.cpp \
        network/networkutility.cpp \
        main.cpp \
        packetmanager.cpp \
        stdafx.cpp

HEADERS += \
    arpspoofer.h \
    network/l2/l2.h \
    network/l3/arppacket.h \
    network/l3/icmppacket.h \
    network/l3/ippacket.h \
    network/l3/l3.h \
    network/l4/l4.h \
    network/l4/tcppacket.h \
    network/l4/udppacket.h \
    network/networkpacket.h \
    network/networkutility.h \
    packetmanager.h \
    stdafx.h
