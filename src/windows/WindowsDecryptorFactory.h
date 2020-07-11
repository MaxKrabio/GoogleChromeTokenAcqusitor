#pragma once
#include "../utils/decrypt/IDecryptorFactory.h"

namespace crypt
{
    class WindowsDecryptorFactory final : public IDecryptorFactory
    {
    public:
        explicit WindowsDecryptorFactory(const RawVector& passwd);

    public:
        IDataDecrypt* createDecryptor(ChromeVersion ver) override;
    private:
        RawVector _passwd;
    };
}
