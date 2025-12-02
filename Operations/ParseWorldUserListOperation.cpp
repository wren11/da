#include "pch.h"

#include "Operations/ParseWorldUserListOperation.h"
#include "Memory/MemoryManager.h"

namespace DarkAges {
    namespace Operations {
        ParseWorldUserListOperation::ParseWorldUserListOperation(Core::IMemoryManager& memory, uintptr_t packetDataPtr)
            : OperationBase(memory), packetDataPtr_(packetDataPtr), worldCount_(0), result_(0) {
        }

        bool ParseWorldUserListOperation::Execute() {
            auto& mm = static_cast<Memory::MemoryManager&>(memory_manager_);

            // Clear any existing users
            users_.clear();

            // Read packet data directly from memory
            // Based on sub_55C7D0 disassembly:

            // v2 = sub_564270((unsigned __int8 *)(a2 + 1)); // Read world count (16-bit)
            uint16_t worldCount = 0;
            if (!mm.Read((LPVOID)(packetDataPtr_ + 0), (BYTE*)&worldCount, sizeof(uint16_t))) {
                return false;
            }
            worldCount_ = worldCount;

            // v20 = (unsigned __int16)sub_564270((unsigned __int8 *)(a2 + 3)); // Read user count (8-bit)
            uint8_t userCountByte = 0;
            if (!mm.Read((LPVOID)(packetDataPtr_ + 1), (BYTE*)&userCountByte, sizeof(uint8_t))) {
                return false;
            }
            uint16_t userCount = userCountByte;

            // Start parsing at offset 4 (after packet type, 16-bit world count, and 8-bit user count)
            int dataOffset = 4;

            // Parse each user entry
            for (uint16_t i = 0; i < userCount; i++) {
                WorldListUser user;

                // Read class/flags byte: v3 = std::char_traits<char>::to_char_type(v19++ + a2)
                uint8_t classWithFlags = 0;
                if (!mm.Read((LPVOID)(packetDataPtr_ + dataOffset++), (BYTE*)&classWithFlags, sizeof(uint8_t))) {
                    return false;
                }

                // Extract character class: v14 = v3 & 7
                // This determines which UI icon/skin to show (0-7 range)
                // UI element updated at: gameObject + 4 * (characterClass + 1) + 1584
                // If characterClass is 0, defaults to index 7
                user.characterClass = classWithFlags & 0x07;

                // Extract flag8: v12 = v3 & 8
                // If this bit is set, shows additional UI element at gameObject + 1616
                // Likely indicates special status like master, GM, or other elevated privileges
                user.flag8 = classWithFlags & 0x08;

                // Extract upper flags: v11 = (signed int)v3 >> 4
                // Upper 4 bits (4-7) - purpose unclear from disassembly
                user.upperFlags = (int8_t)classWithFlags >> 4;

                // Read color: v13 = std::char_traits<char>::to_char_type(v19++ + a2)
                // Used for coloring the user's name/icon in the UI display
                if (!mm.Read((LPVOID)(packetDataPtr_ + dataOffset++), (BYTE*)&user.color, sizeof(uint8_t))) {
                    return false;
                }

                // Read status: v16 = std::char_traits<char>::to_char_type(v19++ + a2)
                // Likely indicates online/offline status or current activity state
                // May affect how the user appears in the list (online indicator, etc.)
                if (!mm.Read((LPVOID)(packetDataPtr_ + dataOffset++), (BYTE*)&user.status, sizeof(uint8_t))) {
                    return false;
                }

                // Read title length: v4 = std::char_traits<char>::to_char_type(v19++ + a2)
                uint8_t titleLength = 0;
                if (!mm.Read((LPVOID)(packetDataPtr_ + dataOffset++), (BYTE*)&titleLength, sizeof(uint8_t))) {
                    return false;
                }

                // Read title string (Lord, Lady, etc.)
                // Displayed before the user's name in the UI
                if (titleLength > 0 && titleLength <= 48) {
                    std::vector<char> titleBuffer(titleLength + 1, 0);
                    if (!mm.Read((LPVOID)(packetDataPtr_ + dataOffset), (BYTE*)titleBuffer.data(), titleLength)) {
                        return false;
                    }
                    user.title = std::string(titleBuffer.data(), titleLength);
                }
                dataOffset += titleLength;

                // Read master flag: v15 = std::char_traits<char>::to_char_type(v19++ + a2)
                // Additional master-level status indicator
                // May control additional UI elements or special display features
                if (!mm.Read((LPVOID)(packetDataPtr_ + dataOffset++), (BYTE*)&user.masterFlag, sizeof(uint8_t))) {
                    return false;
                }

                // Read name length: v9 = std::char_traits<char>::to_char_type(v19++ + a2)
                uint8_t nameLength = 0;
                if (!mm.Read((LPVOID)(packetDataPtr_ + dataOffset++), (BYTE*)&nameLength, sizeof(uint8_t))) {
                    return false;
                }

                // Read name string (character name)
                // Main display name shown in the user/world list UI
                // Limited to 29 characters maximum
                if (nameLength > 0 && nameLength <= 29) {
                    std::vector<char> nameBuffer(nameLength + 1, 0);
                    if (!mm.Read((LPVOID)(packetDataPtr_ + dataOffset), (BYTE*)nameBuffer.data(), nameLength)) {
                        return false;
                    }
                    user.name = std::string(nameBuffer.data(), nameLength);
                }
                dataOffset += nameLength;

                // Add the parsed user to the list
                users_.push_back(user);
            }

            result_ = 1; // Success
            return true;
        }
    }
}
