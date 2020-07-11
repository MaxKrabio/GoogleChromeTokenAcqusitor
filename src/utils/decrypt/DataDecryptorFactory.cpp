#include "../../stdafx.h"
#include "DataDecryptorFactory.h"

#if defined (WIN64)
#include "../../windows/WindowsDecryptorFactory.h"
#elif defined (__linux__)
#include "LinuxDecryptorFactory.h"
#elif defined (__APPLE_)
#include "MacOsDecryptorFactory.h"
#endif

crypt::DataDecryptorFactory::DataDecryptorFactory(const crypt::RawVector& passwd)
    :  _passwd(passwd)
{
}

crypt::IDataDecrypt* crypt::DataDecryptorFactory::createDecryptor(crypt::ChromeVersion ver)
{
    #if defined (WIN64)
    return WindowsDecryptorFactory(_passwd).createDecryptor(ver);
    #elif defined (__linux__)
    return LinuxDecryptorFactory(_passwd).createDecryptor(ver);
    #elif defined (__APPLE_)
    return AppleDecryptorFactory(_passwd).createDecryptor(ver);
    #endif
    return nullptr;
}
