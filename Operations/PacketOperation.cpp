#include "pch.h"
#include "Operations/PacketOperation.h"
#include "Memory/MemoryManager.h"

namespace DarkAges {
    namespace Operations {

        PacketOperation::PacketOperation(Core::IMemoryManager& memory, const std::vector<BYTE>& payload)
            : OperationBase(memory), payload_(payload) {
        }

        bool PacketOperation::Execute() {
            if (payload_.empty()) return false;
            auto& mm = static_cast<Memory::MemoryManager&>(memory_manager_);
            LPVOID sender = mm.ReadPointer(reinterpret_cast<LPVOID>(GameAddresses::SEND_THIS));
            if (!sender) return false;
            LPVOID packet_mem = mm.Allocate(payload_.size());
            if (!packet_mem) return false;
            mm.Write(packet_mem, payload_.data(), payload_.size());
            std::vector<BYTE> shellcode = {
                0x9C, 0x60, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x52, 0xB8, 0x00, 0x00, 0x00, 0x00,
                0x50, 0xB9, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0,
                0x61, 0x9D, 0xC3
            };
            *(DWORD*)&shellcode[3] = static_cast<DWORD>(payload_.size());
            *(DWORD*)&shellcode[9] = reinterpret_cast<DWORD>(packet_mem);
            *(DWORD*)&shellcode[15] = reinterpret_cast<DWORD>(sender);
            *(DWORD*)&shellcode[20] = GameAddresses::FUNC_SEND;
            return mm.InjectShellcode(shellcode);
        }
    }
}