#pragma once
#include "Operations/OperationBase.h"
#include "Operations/GameAddresses.h"

namespace DarkAges {
    namespace Operations {
        class PacketOperation : public OperationBase {
        private:
            std::vector<BYTE> payload_;
        public:
            PacketOperation(Core::IMemoryManager& memory, const std::vector<BYTE>& payload);
            bool Execute() override;
            std::string GetName() const override { return "Packet"; }
        };
    }
}