#pragma once
#include "IDataDecrypt.h"

namespace crypt
{
    enum ChromeVersion
    {
        ChromeVersionUntil79,
        ChromeVersion80AndAbove
    };

    class IDecryptorFactory
    {
    public:
        virtual IDataDecrypt* createDecryptor(ChromeVersion ver) = 0;
    };
}


