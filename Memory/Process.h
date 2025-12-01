#pragma once
#include "pch.h"
#include "Core/IMemoryManager.h"
#include "Memory/MemoryManager.h"

class HookManager;

namespace DarkAges {
    namespace Memory {
        class RingBuffer : public Core::IBuffer {
        private:
            std::vector<BYTE> memory_;
            std::atomic<DWORD> head_;
            std::atomic<DWORD> tail_;
            std::mutex lock_;
            DWORD capacity_;
        public:
            explicit RingBuffer(DWORD capacity);
            bool Write(const BYTE* data, DWORD size) override;
            bool Read(std::vector<BYTE>& out) override;
        };
        class Process : public Core::IProcess {
        private:
            HANDLE process_handle_;
            LPVOID base_address_;
            std::atomic<bool> attached_;
            std::unique_ptr<MemoryManager> memory_manager_;
            std::unique_ptr<RingBuffer> send_buffer_;
            std::unique_ptr<RingBuffer> recv_buffer_;
            std::unique_ptr<HookManager> hook_manager_;
            LPVOID ResolveBaseAddress();
        public:
            explicit Process(DWORD pid);
            ~Process() override;
            HANDLE GetHandle() const override { return process_handle_; }
            LPVOID GetBaseAddress() const override { return base_address_; }
            bool IsAttached() const override { return attached_.load(); }
            void Attach() override;
            void Detach() override;
            Core::IMemoryManager& GetMemoryManager() override { return *memory_manager_; }
            RingBuffer& GetSendBuffer() { return *send_buffer_; }
            RingBuffer& GetRecvBuffer() { return *recv_buffer_; }
            bool InstallHooks(void(__stdcall* send_cb)(const BYTE*, DWORD), void(__stdcall* recv_cb)(const BYTE*, DWORD));
            bool UninstallHooks();
        };
    }
}