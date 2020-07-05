TEMPLATE = app
CONFIG += cmdline c++17 precompile_header

CONFIG += conan_basic_setup
include(conanbuildinfo.pri)

#QMAKE_CC = sccache $$QMAKE_CC
#QMAKE_CXX = sccache $$QMAKE_CXX

PKGCONFIG += openssl
PRECOMPILED_HEADER = stdafx.h


SOURCES += \
    *.cpp \
    DataDecryptorFactory.cpp \
    WindowsDataDecryptor.cpp \
    WindowsDecryptorFactory.cpp \
    WindowsOldDataDecryptor.cpp

HEADERS += \
    *.h \
    DataDecryptorFactory.h \
    IDataDecrypt.h \
    IDecryptorFactory.h \
    WindowsDataDecryptor.h \
    WindowsDecryptorFactory.h \
    WindowsOldDataDecryptor.h
