#include "AesGCMDecryptor.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

crypt::AesGCMDecryptor::AesGCMDecryptor()
{
    if(!(_ctx = EVP_CIPHER_CTX_new()))
    {
        spdlog::error("Can't allocate memory for crypt context!");
    }
}

crypt::AesGCMDecryptor::~AesGCMDecryptor()
{
    EVP_CIPHER_CTX_free(_ctx);
}

bool crypt::AesGCMDecryptor::init()
{
    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(_ctx, _cipherFn(), NULL, NULL, NULL))
    {
        spdlog::error("DecryptInit has been failed!");
        return false;
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_IVLEN, _iv.size(), NULL))
    {
        spdlog::error("IV initialization has been failed!");
        return false;
    }

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(_ctx, NULL, NULL, _decryptKey.data(), _iv.data()))
    {
        spdlog::error("Decrypt context initialization has been failed!");
        return false;
    }
    return true;
}

crypt::AesGCMDecryptor& crypt::AesGCMDecryptor::setCipherType(CipherFnType cipherFn)
{
    _cipherFn = cipherFn;
    return *this;
}

crypt::AesGCMDecryptor& crypt::AesGCMDecryptor::setDecryptKey(const RawVector& key)
{
    _decryptKey = key;
    return *this;
}

crypt::AesGCMDecryptor& crypt::AesGCMDecryptor::setIV(const RawVector& iv)
{
    _iv = iv;
    return *this;
}

bool crypt::AesGCMDecryptor::decrypt(const RawVector& cipherText, RawVector& decryptText)
{
    int decryptSize {0};
    if(!EVP_DecryptUpdate(_ctx,
                          decryptText.data(),
                          &decryptSize,
                          cipherText.data(),
                          cipherText.size()))
    {
        spdlog::error("Can't decrypt data block!");
    }
    return decryptSize != 0;
}

bool crypt::AesGCMDecryptor::decryptFinalize(crypt::RawVector& decryptText)
{
    int len = 0;
    return EVP_DecryptFinal_ex(_ctx, decryptText.data(), &len) > 0 ? true : false;

}
