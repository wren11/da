#pragma once
#include "Operations/IOperation.h"
#include "Operations/GameAddresses.h"

namespace DarkAges {
    namespace Operations {
        class FollowOperation : public OperationBase {
        private:
            DWORD target_id_;
        public:
            FollowOperation(Core::IMemoryManager& memory, DWORD target_id);
            bool Execute() override;
            std::string GetName() const override { return "Follow"; }
        };
    }
}

