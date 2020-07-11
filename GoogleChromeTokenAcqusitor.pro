TEMPLATE = app
CONFIG += cmdline c++17 precompile_header

CONFIG += conan_basic_setup
include($$_PRO_FILE_PWD_/conan/conanbuildinfo.pri)
include($$_PRO_FILE_PWD_/src/utils/utils.pri)
include($$_PRO_FILE_PWD_/src/windows/WinDataDecryptor.pri)
include($$_PRO_FILE_PWD_/src/proj.pri)

PKGCONFIG += openssl
PRECOMPILED_HEADER = src/stdafx.h


