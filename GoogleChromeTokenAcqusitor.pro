TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

CONFIG += conan_basic_setup
include(conanbuildinfo.pri)

PKGCONFIG += openssl
PRECOMPILED_HEADER = stable.h

SOURCES += \
    *.cpp

HEADERS += \
    *.h
