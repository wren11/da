#pragma once
#include "pch.h"

extern "C" {
    typedef void(__stdcall* SendPacketCallback_t)(const BYTE*, DWORD);
    typedef void(__stdcall* RecvPacketCallback_t)(const BYTE*, DWORD);
}

struct PacketCallbackContext {
    void* send_buffer;
    void* recv_buffer;
    std::atomic<bool>* silent_mode;
    std::atomic<DWORD>* serial_id;
    std::string* player_name;
    std::mutex* callback_lock;
    bool (*send_buffer_write)(void* buffer, const BYTE* data, DWORD size);
    bool (*recv_buffer_write)(void* buffer, const BYTE* data, DWORD size);
};

void InitializePacketCallbacks(const PacketCallbackContext& ctx);
void CleanupPacketCallbacks();

extern "C" {
    void __stdcall SendPacketCallback(const BYTE* pkt, DWORD len);
    void __stdcall RecvPacketCallback(const BYTE* pkt, DWORD len);
}

void HandleSendPacket(const BYTE* pkt, DWORD len);
void HandleRecvPacket(const BYTE* pkt, DWORD len);