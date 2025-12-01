#include "pch.h"
#include "Operations/WalkOperation.h"
#include "Memory/MemoryManager.h"

namespace DarkAges {
    namespace Operations {

        WalkOperation::WalkOperation(Core::IMemoryManager& memory, int direction)
            : OperationBase(memory), direction_(direction) {
        }

        bool WalkOperation::Execute() {
            auto& mm = static_cast<Memory::MemoryManager&>(memory_manager_);
            std::vector<BYTE> shellcode = {
                0x60, 0x68, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00,
                0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x61, 0xC3
            };
            *(DWORD*)&shellcode[2] = static_cast<DWORD>(direction_);
            *(DWORD*)&shellcode[7] = GameAddresses::OBJECT_BASE;
            *(DWORD*)&shellcode[12] = GameAddresses::FUNC_WALK;
            return mm.InjectShellcode(shellcode);
        }
    }
}