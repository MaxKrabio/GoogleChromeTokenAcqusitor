#pragma once
#include "IDataDecrypt.h"

namespace crypt
{
    namespace windows
    {
        class WindowsOldDataDecryptor : public IDataDecrypt
        {
        public:
            bool decrypt(const RawVector& cipherText, RawVector& decryptText) override;
        private:
            std::string _passwd;
        };
    }
}


