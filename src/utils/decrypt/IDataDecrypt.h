#pragma once
#include <vector>

namespace crypt
{
    using RawVector = std::vector<unsigned char>;
    class IDataDecrypt
    {
    public:
        virtual bool decrypt(const RawVector& cipherText,
                             RawVector& decryptText) = 0;
        virtual ~IDataDecrypt() {};
    };
}
