#include "pch.h"
#include "Memory/Process.h"
#include "Hooks.h"

namespace DarkAges {
    namespace Memory {

        RingBuffer::RingBuffer(DWORD capacity) : memory_(capacity), head_(0), tail_(0), capacity_(capacity) {}

        bool RingBuffer::Write(const BYTE* data, DWORD size) {
            if (size > capacity_ - 1) return false;
            std::lock_guard<std::mutex> lock(lock_);
            DWORD available = (tail_.load() + capacity_ - head_.load() - 1) % capacity_;
            if (size > available) {
                DWORD advance = size - available;
                tail_.store((tail_.load() + advance) % capacity_);
            }
            *(DWORD*)&memory_[head_] = size;
            head_ = (head_ + sizeof(DWORD)) % capacity_;
            for (DWORD i = 0; i < size; ++i) {
                memory_[head_] = data[i];
                head_ = (head_ + 1) % capacity_;
            }
            return true;
        }

        bool RingBuffer::Read(std::vector<BYTE>& out) {
            std::lock_guard<std::mutex> lock(lock_);
            if (head_ == tail_) return false;
            DWORD size = *(DWORD*)&memory_[tail_];
            tail_ = (tail_ + sizeof(DWORD)) % capacity_;
            if (size > static_cast<DWORD>(out.capacity())) out.resize(size);
            for (DWORD i = 0; i < size; ++i) {
                out[i] = memory_[tail_];
                tail_ = (tail_ + 1) % capacity_;
            }
            out.resize(size);
            return true;
        }

        Process::Process(DWORD pid) : process_handle_(nullptr), base_address_(nullptr), attached_(false) {
            process_handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (!process_handle_) throw std::runtime_error("Failed to open process");
            base_address_ = ResolveBaseAddress();
            if (!base_address_) {
                CloseHandle(process_handle_);
                throw std::runtime_error("Failed to resolve base address");
            }
            memory_manager_ = std::make_unique<MemoryManager>(process_handle_);
            send_buffer_ = std::make_unique<RingBuffer>(1024 * 1024);
            recv_buffer_ = std::make_unique<RingBuffer>(1024 * 1024);
            hook_manager_ = std::make_unique<HookManager>(process_handle_);
        }

        Process::~Process() {
            Detach();
            if (process_handle_) CloseHandle(process_handle_);
        }

        void Process::Attach() {
            if (attached_.load()) return;
            attached_.store(true);
        }

        void Process::Detach() {
            UninstallHooks();
            memory_manager_->CollectGarbage();
            attached_.store(false);
        }

        bool Process::InstallHooks(void(__stdcall* send_cb)(const BYTE*, DWORD), void(__stdcall* recv_cb)(const BYTE*, DWORD)) {
            return hook_manager_ ? hook_manager_->InstallAllHooks(send_cb, recv_cb) : false;
        }

        bool Process::UninstallHooks() {
            return hook_manager_ ? hook_manager_->UninstallAllHooks() : false;
        }

        LPVOID Process::ResolveBaseAddress() {
            HMODULE modules[1024];
            DWORD needed;
            if (EnumProcessModules(process_handle_, modules, sizeof(modules), &needed)) {
                return reinterpret_cast<LPVOID>(modules[0]);
            }
            return nullptr;
        }
    }
}