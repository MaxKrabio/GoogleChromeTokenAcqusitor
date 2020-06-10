#pragma once
#include "stdafx.h"
#include "openssl/ossl_typ.h"

namespace crypt
{
    using RawVector = std::vector<unsigned char>;
    using CipherFnType = const EVP_CIPHER*();

    class AesGCMDecryptor
    {
    public:
        AesGCMDecryptor();
        ~AesGCMDecryptor();
        bool init();
        AesGCMDecryptor& setCipherType(CipherFnType cipherFn);
        AesGCMDecryptor& setDecryptKey(const RawVector& key);
        AesGCMDecryptor& setIV(const RawVector& iv);
        bool decrypt(const RawVector& cipherText, RawVector& decryptText);
        bool decryptFinalize(RawVector& decryptText);

    private:
        EVP_CIPHER_CTX* _ctx;
        RawVector _decryptKey;
        RawVector _iv;
        CipherFnType* _cipherFn;

    };
}
