TEMPLATE = app
CONFIG += cmdline c++17 precompile_header

CONFIG += conan_basic_setup
include(conanbuildinfo.pri)

PKGCONFIG += openssl
PRECOMPILED_HEADER = stable.h

SOURCES += \
    *.cpp

HEADERS += \
    *.h
