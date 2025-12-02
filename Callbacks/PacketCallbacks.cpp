#include "pch.h"
#include "Callbacks/PacketCallbacks.h"
#include "Operations/ParseWorldUserListOperation.h"
#include "Memory/MemoryManager.h"

static PacketCallbackContext g_callback_ctx = { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };

void InitializePacketCallbacks(const PacketCallbackContext& ctx) {
    g_callback_ctx = ctx;
}

void CleanupPacketCallbacks() {
    g_callback_ctx = { nullptr, nullptr, nullptr, nullptr, nullptr, nullptr };
}

void HandleSendPacket(const BYTE* pkt, DWORD len) {
    if (!pkt || len == 0) return;
    bool should_silence = (g_callback_ctx.silent_mode && g_callback_ctx.silent_mode->load());
    if (!should_silence) {
        printf("[OUT] PKT: ");
        for (DWORD i = 0; i < (len < 16 ? len : 16); ++i) printf("%02X ", pkt[i]);
        if (len > 16) printf("... (%u)", len);
        printf("\n");
    }
    if (g_callback_ctx.send_buffer && g_callback_ctx.send_buffer_write) {
        g_callback_ctx.send_buffer_write(g_callback_ctx.send_buffer, pkt, len);
    }
}

void HandleRecvPacket(const BYTE* pkt, DWORD len) {
    if (!pkt || len == 0) return;
    bool should_silence = (g_callback_ctx.silent_mode && g_callback_ctx.silent_mode->load());
    if (!should_silence) {
        printf("[IN ] PKT: ");
        for (DWORD i = 0; i < (len < 16 ? len : 16); ++i) printf("%02X ", pkt[i]);
        if (len > 16) printf("... (%u)", len);
        printf("\n");
    }
    if (len >= 8 && pkt[0] == 0x33 && g_callback_ctx.serial_id && g_callback_ctx.player_name) {
        if (len >= 11) {
            DWORD serial = *(DWORD*)&pkt[7];
            for (size_t i = 11; i < len - 1; ++i) {
                if (pkt[i] > 0 && pkt[i] <= 20) {
                    DWORD nlen = pkt[i];
                    if (i + 1 + nlen <= len) {
                        std::string name((char*)&pkt[i + 1], nlen);
                        if (_stricmp(name.c_str(), g_callback_ctx.player_name->c_str()) == 0) {
                            g_callback_ctx.serial_id->store(serial);
                            printf("[ID ] TARGET_ACQUIRED: %s [0x%08X]\n", name.c_str(), serial);
                        }
                        break;
                    }
                }
            }
        }
    }
    if (g_callback_ctx.recv_buffer && g_callback_ctx.recv_buffer_write) {
        g_callback_ctx.recv_buffer_write(g_callback_ctx.recv_buffer, pkt, len);
    }

    if (len >= 5 && pkt[0] == 0x36) {
        DarkAges::Memory::MemoryManager mm(GetCurrentProcess());
        DarkAges::Operations::ParseWorldUserListOperation op(mm, (uintptr_t)pkt);

        if (op.Execute()) {
            printf("[IN ] WORLD_LIST: WorldCount=%u, UserCount=%u\n", op.GetWorldCount(), op.GetUserCount());
            const auto& users = op.GetUsers();
            for (const auto& user : users) {
                printf("[IN ]   User: %s (Title: %s, Class: %d, Color: %d, Status: %d)\n",
                    user.name.c_str(), user.title.c_str(), user.characterClass, user.color, user.status);
            }
        } else {
            printf("[IN ] WORLD_LIST: Failed to parse packet\n");
        }
    }
}

extern "C" {
    void __stdcall SendPacketCallback(const BYTE* pkt, DWORD len) {
        if (!g_callback_ctx.callback_lock) {
            HandleSendPacket(pkt, len);
            return;
        }
        std::lock_guard<std::mutex> lock(*g_callback_ctx.callback_lock);
        HandleSendPacket(pkt, len);
    }

    void __stdcall RecvPacketCallback(const BYTE* pkt, DWORD len) {
        if (!g_callback_ctx.callback_lock) {
            HandleRecvPacket(pkt, len);
            return;
        }
        std::lock_guard<std::mutex> lock(*g_callback_ctx.callback_lock);
        HandleRecvPacket(pkt, len);
    }
}