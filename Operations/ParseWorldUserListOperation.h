#pragma once

#include "Operations/OperationBase.h"
#include <vector>
#include <string>
#include <cstdint>

namespace DarkAges {
    namespace Operations {
        // Represents a user entry in the world/user list
        // Based on sub_55C7D0 disassembly - exact field mappings
        struct WorldListUser {
            uint8_t characterClass;    // v14 = classWithFlags & 0x07 (0-7, determines UI icon/skin)
                                       // Used to index UI elements: v7 + 4 * (characterClass + 1) + 1584
                                       // If 0, defaults to index 7

            uint8_t flag8;            // v12 = classWithFlags & 0x08 (bit 3 flag)
                                       // If set, shows additional UI element at v7 + 1616
                                       // Likely indicates special status (master, GM, etc.)

            int8_t upperFlags;        // v11 = (signed int)classWithFlags >> 4 (upper 4 bits)
                                       // Purpose unclear from visible code, may be reserved

            uint8_t color;            // v13 (color value for display)
                                       // Used for coloring the user's name/icon in UI

            uint8_t status;           // v16 (status value)
                                       // Likely online/offline status or activity state

            std::string title;        // v17 (title string, up to 48 chars)
                                       // User's title (Lord, Lady, etc.)

            uint8_t masterFlag;       // v15 (master flag)
                                       // Additional master-level indicator

            std::string name;         // v18 (name string, up to 29 chars)
                                       // User's character name
        };

        class ParseWorldUserListOperation : public OperationBase
        {
        public:
            ParseWorldUserListOperation(Core::IMemoryManager& memory, uintptr_t packetDataPtr);
            virtual ~ParseWorldUserListOperation() = default;

            bool Execute() override;
            std::string GetName() const override { return "ParseWorldUserList"; }

            // Get the parsed user list
            const std::vector<WorldListUser>& GetUsers() const { return users_; }

            // Get world count (stored at offset 2116 in game object)
            uint16_t GetWorldCount() const { return worldCount_; }

            // Get user count
            uint16_t GetUserCount() const { return static_cast<uint16_t>(users_.size()); }

        private:
            uintptr_t packetDataPtr_;
            std::vector<WorldListUser> users_;
            uint16_t worldCount_;
            int result_;
        };
    }
}
