#include "../stdafx.h"
#include "WindowsOldDataDecryptor.h"
#include <Windows.h>
#include <wincrypt.h>

bool crypt::windows::WindowsOldDataDecryptor::decrypt(const crypt::RawVector& cipherText, crypt::RawVector& decryptText)
{
    DATA_BLOB inCryptedBlob;
    inCryptedBlob.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*> (cipherText.data()));
    inCryptedBlob.cbData = cipherText.size();
    DATA_BLOB outDecryptedBlob;

    if (!CryptUnprotectData(&inCryptedBlob,
                            NULL,  //&pDescrOut,
                            NULL,  // Optional entropy
                            NULL,  // Reserved
                            NULL,  //&PromptStruct,
                            0,     // Optional PromptStruct
                            &outDecryptedBlob))
    {
        spdlog::error("Can't decrypt key. The last error is:");
        spdlog::error(GetLastError());
        return false;
    }

    decryptText.clear();
    std::copy(static_cast<unsigned char*>(outDecryptedBlob.pbData),
              static_cast<unsigned char *>(outDecryptedBlob.pbData) + outDecryptedBlob.cbData,
              std::back_inserter(decryptText));

    return decryptText.size();
}
