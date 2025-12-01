#include "pch.h"
#include "Config/Configuration.h"

namespace DarkAges {
    namespace Config {

        Configuration::Configuration(const std::string& config_file) : config_file_(config_file) {}

        bool Configuration::Load() {
            std::ifstream file(config_file_);
            if (!file.is_open()) {
                Save();
                return false;
            }
            accounts_.clear();
            std::string line;
            while (std::getline(file, line)) {
                if (line.empty() || line[0] == '#') continue;
                size_t delim = line.find(':');
                if (delim != std::string::npos) {
                    std::string user = line.substr(0, delim);
                    std::string pass = line.substr(delim + 1);
                    user.erase(0, user.find_first_not_of(" \t\r\n"));
                    user.erase(user.find_last_not_of(" \t\r\n") + 1);
                    pass.erase(0, pass.find_first_not_of(" \t\r\n"));
                    pass.erase(pass.find_last_not_of(" \t\r\n") + 1);
                    if (!user.empty() && !pass.empty()) {
                        accounts_.push_back({ user, pass });
                    }
                }
            }
            return true;
        }

        bool Configuration::Save() {
            std::ofstream file(config_file_);
            if (!file.is_open()) return false;
            for (const auto& account : accounts_) {
                file << account.username << ":" << account.password << "\n";
            }
            return true;
        }

        void Configuration::AddAccount(const std::string& username, const std::string& password) {
            accounts_.push_back({ username, password });
        }

    }
}