#pragma once
#include "IDecryptorFactory.h"

namespace crypt
{
    class DataDecryptorFactory : public IDecryptorFactory
    {
    public:
        explicit DataDecryptorFactory(const RawVector& passwd);

        // IDecryptorFactory interface
    public:
        IDataDecrypt* createDecryptor(ChromeVersion ver) override;

    private:
        RawVector _passwd;
    };
}


