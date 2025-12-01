#pragma once
#include "pch.h"
#include "Core/IMemoryManager.h"

namespace DarkAges {
    namespace Memory {
        struct AllocationInfo {
            LPVOID address;
            std::chrono::steady_clock::time_point timestamp;
            size_t size;
        };
        class MemoryManager : public Core::IMemoryManager {
        private:
            HANDLE process_handle_;
            std::vector<AllocationInfo> allocations_;
            std::mutex allocation_lock_;
            static constexpr DWORD MAX_ALLOCATION_AGE_MS = 300000;
        public:
            explicit MemoryManager(HANDLE process);
            ~MemoryManager() override;
            LPVOID Allocate(size_t size) override;
            bool Deallocate(LPVOID ptr) override;
            bool Write(LPVOID addr, const void* data, size_t size) override;
            bool Read(LPVOID addr, void* buffer, size_t size) override;
            LPVOID ReadPointer(LPVOID addr) override;
            void CollectGarbage() override;
            bool InjectShellcode(const std::vector<BYTE>& payload, LPVOID param = nullptr);
        };
    }
}