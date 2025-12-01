#include "pch.h"
#include "Operations/LoginOperation.h"
#include "Memory/MemoryManager.h"

namespace DarkAges {
    namespace Operations {

        LoginOperation::LoginOperation(Core::IMemoryManager& memory, const std::string& user, const std::string& pass)
            : OperationBase(memory), username_(user), password_(pass) {
        }

        bool LoginOperation::Execute() {
            auto& mm = static_cast<Memory::MemoryManager&>(memory_manager_);
            LPVOID user_mem = mm.Allocate(username_.size() + 1);
            LPVOID pass_mem = mm.Allocate(password_.size() + 1);
            if (!user_mem || !pass_mem) return false;
            mm.Write(user_mem, username_.c_str(), username_.size() + 1);
            mm.Write(pass_mem, password_.c_str(), password_.size() + 1);
            std::vector<BYTE> shellcode = {
                0x83, 0xEC, 0x04, 0x68, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00,
                0xB9, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xD9, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0,
                0x83, 0xC4, 0x04, 0x8B, 0xCB, 0x83, 0xEC, 0x04, 0x68, 0x00, 0x00, 0x00, 0x00,
                0x68, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x11, 0x8B, 0x42, 0x24, 0xFF, 0xD0, 0x83, 0xC4, 0x04,
                0x6A, 0x02, 0x6A, 0x03, 0x50, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x83, 0xC4, 0x0C,
                0x83, 0xEC, 0x04, 0x53, 0x68, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xD0, 0x83, 0xC4, 0x0C, 0xC3
            };
            *(DWORD*)&shellcode[4] = reinterpret_cast<DWORD>(pass_mem);
            *(DWORD*)&shellcode[9] = reinterpret_cast<DWORD>(user_mem);
            *(DWORD*)&shellcode[14] = GameAddresses::OBJECT_BASE;
            *(DWORD*)&shellcode[20] = GameAddresses::FUNC_LOGIN;
            *(DWORD*)&shellcode[28] = reinterpret_cast<DWORD>(pass_mem);
            *(DWORD*)&shellcode[33] = reinterpret_cast<DWORD>(user_mem);
            *(DWORD*)&shellcode[44] = GameAddresses::FUNC_POST_LOGIN_1;
            *(DWORD*)&shellcode[54] = GameAddresses::DATA_POST_LOGIN_STATIC;
            *(DWORD*)&shellcode[59] = GameAddresses::FUNC_POST_LOGIN_2;
            bool result = mm.InjectShellcode(shellcode);
            if (result) Sleep(2000);
            return result;
        }
    }
}