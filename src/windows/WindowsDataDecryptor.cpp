#include "../stdafx.h"
#include "WindowsDataDecryptor.h"
#include "../utils/decrypt/AesGCMDecryptor.h"

#include "openssl/evp.h"

namespace
{
    constexpr size_t s_encHeaderSize = 3;
    constexpr size_t s_encIVOffset = s_encHeaderSize + 12;
    constexpr size_t s_encGcmTagSize = 16;
}

crypt::windows::WindowsDataDecryptor::WindowsDataDecryptor(const RawVector& upasswd)
    : _upasswd(upasswd)
{
}

bool crypt::windows::WindowsDataDecryptor::decrypt(const crypt::RawVector& cipherText, crypt::RawVector& decryptText)
{
    crypt::RawVector iv(cipherText.begin() + s_encHeaderSize, cipherText.begin() + s_encIVOffset);
    crypt::RawVector tag(cipherText.end() - s_encGcmTagSize, cipherText.end());
    crypt::RawVector cipherTextData (cipherText.begin() + s_encIVOffset, cipherText.end() - s_encGcmTagSize);

    crypt::AesGCMDecryptor decryptor;
    if (!decryptor.setCipherType(EVP_aes_256_gcm).setIV(iv).setDecryptKey(_upasswd).init())
    {
        spdlog::error("Can't initialize aes decrpytion!");
        return false;
    }

    decryptText.resize(cipherTextData.size());
    return decryptor.decrypt(cipherTextData, decryptText);
}
