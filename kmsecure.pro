TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    blowfish.cpp \
    kmsecure.cpp

include(deployment.pri)
qtcAddDeployment()

HEADERS += \
    blowfish.h \
    kmsecure.h \
    tinydir.h

