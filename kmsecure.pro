TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
QMAKE_LFLAGS = -static -static-libgcc

SOURCES += main.cpp \
    blowfish.cpp \
    kmsecure.cpp

include(deployment.pri)

HEADERS += \
    blowfish.h \
    kmsecure.h \
    tinydir.h

