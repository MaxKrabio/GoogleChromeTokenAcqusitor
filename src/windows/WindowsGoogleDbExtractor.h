#pragma once
#include "../GoogleDbExtractorBase.h"

namespace google
{
    class WindowsGoogleDbExtractor : public GoogleDbExtractorBase
    {
    public:
        WindowsGoogleDbExtractor();
        explicit WindowsGoogleDbExtractor(const std::string& userName);
        virtual std::string GetGoogleChromeSystemDir() override;

    protected:
        crypt::ChromeVersion GetVersion() override;

    private:
        virtual void GetKey(std::vector<unsigned char>& dbKey) override;
        std::string GetUName() override;
    };
}

