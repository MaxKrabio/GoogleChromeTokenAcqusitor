#include "WindowsDecryptorFactory.h"
#include "WindowsOldDataDecryptor.h"
#include "WindowsDataDecryptor.h"

crypt::WindowsDecryptorFactory::WindowsDecryptorFactory(const crypt::RawVector& passwd)
    : _passwd(passwd)
{
}

crypt::IDataDecrypt* crypt::WindowsDecryptorFactory::createDecryptor(crypt::ChromeVersion ver)
{
    switch (ver)
    {
    case ChromeVersionUntil79:
        return new windows::WindowsOldDataDecryptor;
    case ChromeVersion80AndAbove:
        return new windows::WindowsDataDecryptor(_passwd);
    default:
            break;
    }
    return nullptr;
}
