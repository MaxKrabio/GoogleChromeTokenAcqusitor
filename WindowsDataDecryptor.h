#pragma once
#include "IDataDecrypt.h"

namespace crypt
{
    namespace windows
    {
        class WindowsDataDecryptor : public IDataDecrypt
        {
        public:
            explicit WindowsDataDecryptor(const RawVector& upasswd);
        public:
            bool decrypt(const RawVector& cipherText, RawVector& decryptText) override;

        private:
            RawVector _upasswd;
        };
    }
}

