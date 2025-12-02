#include "pch.h"
#include "Operations/FollowOperation.h"
#include "Memory/MemoryManager.h"

namespace DarkAges {
    namespace Operations {

        FollowOperation::FollowOperation(Core::IMemoryManager& memory, DWORD target_id)
            : OperationBase(memory), target_id_(target_id) {
        }

        bool FollowOperation::Execute() {
            auto& mm = static_cast<Memory::MemoryManager&>(memory_manager_);
            std::vector<BYTE> shellcode = {
                0x60,                         // PUSHAD
                0x68, 0x00, 0x00, 0x00, 0x00, // PUSH target_id
                0xB9, 0x00, 0x00, 0x00, 0x00, // MOV ECX, OBJECT_BASE
                0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, FUNC_FOLLOW
                0xFF, 0xD0,                   // CALL EAX
                0x61,                         // POPAD
                0xC3                          // RET
            };

            *(DWORD*)&shellcode[2]  = target_id_;
            *(DWORD*)&shellcode[7]  = GameAddresses::OBJECT_BASE;
            *(DWORD*)&shellcode[12] = GameAddresses::FUNC_FOLLOW;

            return mm.InjectShellcode(shellcode);
        }
    }
}

