#pragma once
#include "Operations/OperationBase.h"
#include "Operations/GameAddresses.h"

namespace DarkAges {
    namespace Operations {
        class LoginOperation : public OperationBase {
        private:
            std::string username_;
            std::string password_;
        public:
            LoginOperation(Core::IMemoryManager& memory, const std::string& user, const std::string& pass);
            bool Execute() override;
            std::string GetName() const override { return "Login"; }
        };
    }
}