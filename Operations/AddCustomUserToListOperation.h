#pragma once

#include "Operations/IOperation.h"
#include "Operations/OperationBase.h"
#include <string>
#include <cstdint>

namespace DarkAges {
    namespace Operations {
        class AddCustomUserToListOperation : public OperationBase
        {
        public:
            AddCustomUserToListOperation(Core::IMemoryManager& memory,
                                       const std::string& name,
                                       const std::string& title = "",
                                       uint8_t characterClass = 0,
                                       uint8_t color = 0,
                                       uint8_t status = 1,
                                       bool isMaster = false,
                                       bool hasSpecialFlag = false);

            virtual ~AddCustomUserToListOperation() = default;

            bool Execute() override;
            std::string GetName() const override { return "AddCustomUserToList"; }

        private:
            std::string name_;
            std::string title_;
            uint8_t characterClass_;
            uint8_t color_;
            uint8_t status_;
            bool isMaster_;
            bool hasSpecialFlag_;
            int result_;
        };
    }
}
