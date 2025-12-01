#pragma once
#include "pch.h"

namespace DarkAges {
    namespace Config {
        struct Credentials {
            std::string username;
            std::string password;
        };
        class Configuration {
        private:
            std::vector<Credentials> accounts_;
            std::string config_file_;
        public:
            explicit Configuration(const std::string& config_file = "credentials.conf");
            bool Load();
            bool Save();
            const std::vector<Credentials>& GetAccounts() const { return accounts_; }
            void AddAccount(const std::string& username, const std::string& password);
        };
    }
}