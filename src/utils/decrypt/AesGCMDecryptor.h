#pragma once
#include "../../stdafx.h"
#include "IDataDecrypt.h"
#include "openssl/ossl_typ.h"

namespace crypt
{
    using CipherFnType = const EVP_CIPHER*();

    class AesGCMDecryptor : public IDataDecrypt
    {
    public:
        AesGCMDecryptor();
        ~AesGCMDecryptor();
        bool init();
        AesGCMDecryptor& setCipherType(CipherFnType cipherFn);
        AesGCMDecryptor& setDecryptKey(const RawVector& key);
        AesGCMDecryptor& setIV(const RawVector& iv);
        virtual bool decrypt(const RawVector& cipherText,
                             RawVector& decryptText) override;
        bool decryptFinalize(RawVector& decryptText);

    private:
        EVP_CIPHER_CTX* _ctx;
        RawVector _decryptKey;
        RawVector _iv;
        CipherFnType* _cipherFn;

    };
}
