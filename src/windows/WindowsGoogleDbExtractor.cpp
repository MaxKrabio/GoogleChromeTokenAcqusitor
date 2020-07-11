#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Advapi32.lib")

#include "WindowsGoogleDbExtractor.h"
#include <windows.h>
#include "json/json.h"
#include "../utils/base64.h"
#include "WindowsOldDataDecryptor.h"
#include <streambuf>
#include <charconv>

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
    constexpr DWORD dpApiOffsetSize = 5;
    const std::string fileWithPasswordPath = GetGoogleChromeSystemDir().append("Local State");

    if (GetVersion() == crypt::ChromeVersionUntil79)
        return;


    Json::Value root;
    std::ifstream configDoc(fileWithPasswordPath, std::ifstream::binary);
    configDoc >> root;

    Json::Value encKeyObj = root["os_crypt"]["encrypted_key"];
    const std::string base64EncKey = encKeyObj.asString();
    std::string winCryptedKey = base64_decode(base64EncKey, true);

    crypt::RawVector rawCryptedKey(winCryptedKey.begin() + dpApiOffsetSize, winCryptedKey.end());

    crypt::windows::WindowsOldDataDecryptor().decrypt(rawCryptedKey, dbKey);
}

std::string google::WindowsGoogleDbExtractor::GetGoogleChromeSystemDir()
{
    return std::string("C:\\Users\\").append(GetUName()).append("\\AppData\\Local\\Google\\Chrome\\User Data\\");
}

crypt::ChromeVersion google::WindowsGoogleDbExtractor::GetVersion()
{
    const static std::string s_googleChromeVerPath
            = GetGoogleChromeSystemDir() + "Last Version";

    std::ifstream verFile(s_googleChromeVerPath);

    const std::string verString((std::istreambuf_iterator<char>(verFile)), std::istreambuf_iterator<char>());

    unsigned int value {0};
    const auto res = std::from_chars(verString.data(), verString.data() + verString.size(), value);
    if (!res.ptr)
    {
        spdlog::error("Google Chrome version parsing has been failed!");
    }

    if (value == 79)
        return crypt::ChromeVersionUntil79;

    return crypt::ChromeVersion80AndAbove;
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
