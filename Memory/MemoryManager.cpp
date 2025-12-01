#include "pch.h"
#include "Memory/MemoryManager.h"

namespace DarkAges {
    namespace Memory {

        MemoryManager::MemoryManager(HANDLE process) : process_handle_(process) {}
        MemoryManager::~MemoryManager() {
            std::lock_guard<std::mutex> lock(allocation_lock_);
            for (const auto& alloc : allocations_) {
                VirtualFreeEx(process_handle_, alloc.address, 0, MEM_RELEASE);
            }
            allocations_.clear();
        }

        LPVOID MemoryManager::Allocate(size_t size) {
            LPVOID ptr = VirtualAllocEx(process_handle_, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (ptr) {
                std::lock_guard<std::mutex> lock(allocation_lock_);
                allocations_.push_back({ ptr, std::chrono::steady_clock::now(), size });
            }
            return ptr;
        }

        bool MemoryManager::Deallocate(LPVOID ptr) {
            std::lock_guard<std::mutex> lock(allocation_lock_);
            auto it = std::find_if(allocations_.begin(), allocations_.end(),
                [ptr](const AllocationInfo& info) { return info.address == ptr; });
            if (it != allocations_.end()) {
                allocations_.erase(it);
                return VirtualFreeEx(process_handle_, ptr, 0, MEM_RELEASE) != 0;
            }
            return false;
        }

        bool MemoryManager::Write(LPVOID addr, const void* data, size_t size) {
            SIZE_T written;
            return WriteProcessMemory(process_handle_, addr, data, size, &written) && written == size;
        }

        bool MemoryManager::Read(LPVOID addr, void* buffer, size_t size) {
            SIZE_T read;
            return ReadProcessMemory(process_handle_, addr, buffer, size, &read) && read == size;
        }

        LPVOID MemoryManager::ReadPointer(LPVOID addr) {
            LPVOID value;
            if (Read(addr, &value, sizeof(LPVOID))) return value;
            return nullptr;
        }

        void MemoryManager::CollectGarbage() {
            auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(allocation_lock_);
            allocations_.erase(std::remove_if(allocations_.begin(), allocations_.end(),
                [this, now](const AllocationInfo& info) {
                    auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - info.timestamp).count();
                    if (age > MAX_ALLOCATION_AGE_MS) {
                        VirtualFreeEx(process_handle_, info.address, 0, MEM_RELEASE);
                        return true;
                    }
                    return false;
                }), allocations_.end());
        }

        bool MemoryManager::InjectShellcode(const std::vector<BYTE>& payload, LPVOID param) {
            LPVOID code_ptr = Allocate(payload.size());
            if (!code_ptr) return false;
            if (!Write(code_ptr, payload.data(), payload.size())) {
                Deallocate(code_ptr);
                return false;
            }
            HANDLE thread = CreateRemoteThread(process_handle_, nullptr, 0, (LPTHREAD_START_ROUTINE)code_ptr, param, 0, nullptr);
            if (!thread) {
                Deallocate(code_ptr);
                return false;
            }
            WaitForSingleObject(thread, 2000);
            CloseHandle(thread);
            return true;
        }
    }
}