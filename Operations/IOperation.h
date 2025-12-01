#pragma once
#include "Core/IMemoryManager.h"

namespace DarkAges {
    namespace Operations {
        class IOperation {
        public:
            virtual ~IOperation() = default;
            virtual bool Execute() = 0;
            virtual std::string GetName() const = 0;
        };
        class OperationBase : public IOperation {
        protected:
            Core::IMemoryManager& memory_manager_;
        public:
            explicit OperationBase(Core::IMemoryManager& memory) : memory_manager_(memory) {}
        };
    }
}