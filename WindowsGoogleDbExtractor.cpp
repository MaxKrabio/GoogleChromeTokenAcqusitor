#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Advapi32.lib")

#include "WindowsGoogleDbExtractor.h"
#include <windows.h>
#include <windows.h>
#include <Wincrypt.h>
#include "json/json.h"
#include "base64.h"

google::WindowsGoogleDbExtractor::WindowsGoogleDbExtractor()
{
    _userName = GetUName();
}

google::WindowsGoogleDbExtractor::WindowsGoogleDbExtractor(const std::string& userName)
{
    _userName = userName;
}

void google::WindowsGoogleDbExtractor::GetKey(std::vector<unsigned char>& dbKey)
{
    std::string fileWithPasswordPath = GetGoogleChromeSystemDir().append("Local State");

    Json::Value root;
    std::ifstream configDoc(fileWithPasswordPath, std::ifstream::binary);
    configDoc >> root;

    Json::Value encKeyObj = root["os_crypt"]["encrypted_key"];
    const std::string base64EncKey = encKeyObj.asString();
    std::string winCryptedKey = base64_decode(base64EncKey, true);

    DATA_BLOB inCryptedBlob;
    constexpr DWORD dpApiOffsetSize = 5;
    inCryptedBlob.pbData = const_cast<BYTE*>(reinterpret_cast<BYTE*> (winCryptedKey.data() + dpApiOffsetSize));
    inCryptedBlob.cbData = winCryptedKey.size() - dpApiOffsetSize;
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
        return;
    }
    std::copy(static_cast<unsigned char*>(outDecryptedBlob.pbData),
              static_cast<unsigned char *>(outDecryptedBlob.pbData) + outDecryptedBlob.cbData,
              std::back_inserter(dbKey));
}

std::string google::WindowsGoogleDbExtractor::GetGoogleChromeSystemDir()
{
    return std::string("C:\\Users\\").append(GetUName()).append("\\AppData\\Local\\Google\\Chrome\\User Data\\");
}

std::string google::WindowsGoogleDbExtractor::GetUName()
{
    constexpr size_t uNameSize = 256;
    std::string username(uNameSize, '\0');
    DWORD username_len = uNameSize;
    GetUserNameA(username.data(), &username_len);
    username.resize(username_len - 1);
    return username;
}
