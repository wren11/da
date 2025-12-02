#pragma once
#include "Operations/OperationBase.h"
#include "Operations/GameAddresses.h"

namespace DarkAges {
    namespace Operations {
        class WalkOperation : public OperationBase {
        private:
            int direction_;
        public:
            WalkOperation(Core::IMemoryManager& memory, int direction);
            bool Execute() override;
            std::string GetName() const override { return "Walk"; }
        };
    }
}