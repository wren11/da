#pragma once

#include "Operations/IOperation.h"
#include "Core/IMemoryManager.h"

namespace DarkAges {
    namespace Operations {
        class OperationBase : public IOperation {
        protected:
            Core::IMemoryManager& memory_manager_;

        public:
            explicit OperationBase(Core::IMemoryManager& memory) : memory_manager_(memory) {}
            virtual ~OperationBase() = default;
        };
    }
}
