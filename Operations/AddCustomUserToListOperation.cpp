#include "pch.h"

#include "Operations/AddCustomUserToListOperation.h"
#include "Memory/MemoryManager.h"

namespace DarkAges {
    namespace Operations {
        AddCustomUserToListOperation::AddCustomUserToListOperation(Core::IMemoryManager& memory,
                                                                 const std::string& name,
                                                                 const std::string& title,
                                                                 uint8_t characterClass,
                                                                 uint8_t color,
                                                                 uint8_t status,
                                                                 bool isMaster,
                                                                 bool hasSpecialFlag)
            : OperationBase(memory), name_(name), title_(title), characterClass_(characterClass),
              color_(color), status_(status), isMaster_(isMaster), hasSpecialFlag_(hasSpecialFlag), result_(0) {
        }

        bool AddCustomUserToListOperation::Execute() {
            auto& mm = static_cast<Memory::MemoryManager&>(memory_manager_);

            // Allocate memory for return value
            LPVOID resultAddr = mm.Allocate(sizeof(int));
            if (!resultAddr) {
                return false;
            }

            // Use a high user index for custom entries (avoiding conflict with real users)
            // Real users start from index 50+ in the parsing, so we'll use 1000+ for custom
            static int nextCustomIndex = 1000;
            int userIndex = nextCustomIndex++;

            DWORD gameObjectAddr = 0x0073D958;  // Game object base

            // Build shellcode that calls the UI update functions directly
            // Based on sub_55C7D0 disassembly, these functions update the UI with user data
            std::vector<BYTE> shellcode = {
                0x60,                                           // pushad

                // Push user index onto stack for UI calls
                0x68, 0x00, 0x00, 0x00, 0x00,                 // push userIndex

                // UI Update Call 1: Update main UI list
                // Call: sub_55C7D0 style UI update at gameObject + 2100
                0xB9, 0x00, 0x00, 0x00, 0x00,                 // mov ecx, gameObjectAddr
                0x81, 0xC1, 0x3C, 0x08, 0x00, 0x00,           // add ecx, 2100
                0x8B, 0x09,                                   // mov ecx, [ecx] (get UI object)
                0x6A, 0x01,                                   // push 1 (parameter)
                0x51,                                           // push ecx (UI object - thiscall)
                0xB8, 0x00, 0x00, 0x00, 0x00,                 // mov eax, UI update function
                0xFF, 0xD0,                                    // call UI update

                // UI Update Call 2: Update character display UI
                // Call: sub_55C7D0 style UI update at gameObject + 1584
                0xB9, 0x00, 0x00, 0x00, 0x00,                 // mov ecx, gameObjectAddr
                0x81, 0xC1, 0x90, 0x06, 0x00, 0x00,           // add ecx, 1584
                0x8B, 0x09,                                   // mov ecx, [ecx] (get UI object)
                0x6A, 0x01,                                   // push 1 (parameter)
                0x51,                                           // push ecx (UI object - thiscall)
                0xB8, 0x00, 0x00, 0x00, 0x00,                 // mov eax, UI update function
                0xFF, 0xD0,                                    // call UI update

                // Character class specific UI update
                // Calculate: v6 = characterClass ? characterClass + 1 : 7
                // Then call UI update at gameObject + 4 * v6 + 1584
                0xB9, 0x00, 0x00, 0x00, 0x00,                 // mov ecx, gameObjectAddr
                0x81, 0xC1, 0x90, 0x06, 0x00, 0x00,           // add ecx, 1584 (base)
                // Add 4 * (characterClass + 1) - we'll hardcode for now
                0x81, 0xC1, 0x04, 0x00, 0x00, 0x00,           // add ecx, 4 (for class 0 -> index 1)
                0x8B, 0x09,                                   // mov ecx, [ecx] (get UI object)
                0x6A, 0x01,                                   // push 1 (parameter)
                0x51,                                           // push ecx (UI object - thiscall)
                0xB8, 0x00, 0x00, 0x00, 0x00,                 // mov eax, UI update function
                0xFF, 0xD0,                                    // call UI update

                // Success
                0xB8, 0x01, 0x00, 0x00, 0x00,                 // mov eax, 1
                0xA3, 0x00, 0x00, 0x00, 0x00,                 // mov [resultAddr], eax

                0x61,                                           // popad
                0xC3                                            // ret
            };

            // Fill in addresses - we need to find the actual UI update function addresses
            // These would need to be determined by analyzing the vtable entries
            *(DWORD*)&shellcode[1] = userIndex;
            *(DWORD*)&shellcode[3] = gameObjectAddr;
            *(DWORD*)&shellcode[9] = gameObjectAddr;
            *(DWORD*)&shellcode[15] = gameObjectAddr;
            *(DWORD*)&shellcode[shellcode.size() - 7] = reinterpret_cast<DWORD>(resultAddr);

            // For the UI update functions, we need to call the virtual functions
            // This is complex and would require knowing the exact vtable layout
            // For now, this is a framework - the actual function addresses would need
            // to be determined through reverse engineering

            bool result = mm.InjectShellcode(shellcode);

            // Read the return value
            if (result) {
                if (mm.Read(resultAddr, (BYTE*)&result_, sizeof(int))) {
                    result = (result_ == 1);
                } else {
                    result_ = 0;
                    result = false;
                }
            } else {
                result_ = 0;
            }

            // Clean up
            mm.Deallocate(resultAddr);

            return result;
        }
    }
}
