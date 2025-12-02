#pragma once
#include "pch.h"

// =========================================================================================
// [ 0x00 ] CORE DATA STRUCTURES
// =========================================================================================
struct RingBufferSlot {
    volatile LONG seq_num;          // [SEQ] SEQUENCE_ID
    DWORD size;                     // [LEN] DATA_LENGTH
    BYTE payload[4088];             // [BUF] RAW_DATA
};

struct RingBufferHeader {
    volatile LONG seq_write;        // [PTR] WRITE_HEAD
    volatile LONG seq_read;         // [PTR] READ_HEAD
    DWORD total_size;               // [CFG] BUFFER_SIZE
    DWORD slot_count;               // [CFG] SLOT_COUNT
    DWORD slot_size;                // [CFG] SLOT_SIZE
};

// =========================================================================================
// [ 0x01 ] REMOTE BUFFER INTERFACE
// =========================================================================================
class RemoteRingBuffer {
private:
    HANDLE h_proc_;
    LPVOID remote_addr_;
    RingBufferHeader header_;
    std::vector<BYTE> cache_slot_;
    std::mutex lock_;

public:
    RemoteRingBuffer(HANDLE h_proc, size_t count = 1024, size_t size = 4096) :
        h_proc_(h_proc), remote_addr_(nullptr) {

        if (size < sizeof(RingBufferSlot)) throw std::runtime_error("INVALID_SLOT_SIZE");

        size_t hdr_sz = sizeof(RingBufferHeader);
        size_t data_sz = count * size;
        size_t total_sz = hdr_sz + data_sz;

        remote_addr_ = VirtualAllocEx(h_proc_, nullptr, total_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote_addr_) throw std::runtime_error("REMOTE_ALLOC_FAIL");

        header_.seq_write = 0;
        header_.seq_read = 0;
        header_.total_size = (DWORD)total_sz;
        header_.slot_count = (DWORD)count;
        header_.slot_size = (DWORD)size;

        SIZE_T written;
        if (!WriteProcessMemory(h_proc_, remote_addr_, &header_, sizeof(RingBufferHeader), &written)) {
            VirtualFreeEx(h_proc_, remote_addr_, 0, MEM_RELEASE);
            throw std::runtime_error("REMOTE_INIT_FAIL");
        }

        std::vector<BYTE> zero_buf(size, 0);
        for (size_t i = 0; i < count; ++i) {
            LPVOID slot = GetSlotAddr(i);
            WriteProcessMemory(h_proc_, slot, zero_buf.data(), size, &written);
        }

        cache_slot_.resize(size);
    }

    ~RemoteRingBuffer() {
        if (remote_addr_) VirtualFreeEx(h_proc_, remote_addr_, 0, MEM_RELEASE);
    }

    LPVOID GetBase() const { return remote_addr_; }

    LPVOID GetSlotAddr(size_t idx) const {
        return (LPVOID)((DWORD)remote_addr_ + sizeof(RingBufferHeader) + idx * header_.slot_size);
    }

    size_t GetSlotIdx(LONG seq) const {
        return (size_t)(seq % header_.slot_count);
    }

    bool ReadPacket(std::vector<BYTE>& out) {
        RingBufferHeader cur;
        SIZE_T read;
        
        if (!ReadProcessMemory(h_proc_, remote_addr_, &cur, sizeof(RingBufferHeader), &read)) return false;

        if (cur.seq_read >= cur.seq_write) return false;

        size_t idx = GetSlotIdx(cur.seq_read);
        LPVOID slot_ptr = GetSlotAddr(idx);

        if (!ReadProcessMemory(h_proc_, slot_ptr, cache_slot_.data(), header_.slot_size, &read)) return false;

        RingBufferSlot* slot = (RingBufferSlot*)cache_slot_.data();

        if (slot->seq_num != cur.seq_read || slot->size > header_.slot_size - 8) return false;

        out.resize(slot->size);
        memcpy(out.data(), slot->payload, slot->size);

        cur.seq_read++;
        SIZE_T written;
        WriteProcessMemory(h_proc_, remote_addr_, &cur, sizeof(RingBufferHeader), &written);

        return true;
    }
};

// =========================================================================================
// [ 0x02 ] HOOKING INFRASTRUCTURE
// =========================================================================================
class FunctionHook {
protected:
    HANDLE h_proc_;
    LPVOID target_func_;
    LPVOID trampoline_;
    LPVOID helper_addr_;
    std::vector<BYTE> orig_bytes_;
    bool is_installed_;
    bool has_original_bytes_;

public:
    FunctionHook(HANDLE h_proc, LPVOID target) :
        h_proc_(h_proc), target_func_(target), trampoline_(nullptr), helper_addr_(nullptr), is_installed_(false), has_original_bytes_(false) {}

    virtual ~FunctionHook() { ForceUninstall(); }
    virtual bool Install() = 0;
    virtual bool Uninstall() { return false; }
    bool IsInstalled() const { return is_installed_; }

protected:
    // Check if a hook is already installed at the target address
    bool IsHookPresent(size_t hook_size) {
        std::vector<BYTE> current_bytes(hook_size);
        SIZE_T read;
        if (!ReadProcessMemory(h_proc_, target_func_, current_bytes.data(), hook_size, &read) || read != hook_size) {
            return false;
        }
        // Check for jump instruction (0xE9) - our hook signature
        return current_bytes[0] == 0xE9;
    }

    // Backup original bytes, but only if not already backed up or if hook is present
    bool Backup(size_t size) {
        // If we already have original bytes and no hook is present, we're good
        if (has_original_bytes_ && !IsHookPresent(size)) {
            return true;
        }

        // If hook is present, CleanupExistingHook should have been called first
        // But if we're here, try to recover bytes (CleanupExistingHook will handle freeing allocations)
        if (IsHookPresent(size)) {
            // Read the hook to find the trampoline address
            std::vector<BYTE> hook_bytes(6);
            SIZE_T read;
            if (!ReadProcessMemory(h_proc_, target_func_, hook_bytes.data(), 6, &read) || read != 6) {
                return false;
            }
            
            if (hook_bytes[0] == 0xE9) {
                // Calculate trampoline address from relative jump
                DWORD jmp_offset = *(DWORD*)(hook_bytes.data() + 1);
                LPVOID trampoline_addr = (LPVOID)((DWORD)target_func_ + 5 + jmp_offset);
                
                // Read original bytes from trampoline (they're at the start)
                orig_bytes_.resize(size);
                if (!ReadProcessMemory(h_proc_, trampoline_addr, orig_bytes_.data(), size, &read) || read != size) {
                    orig_bytes_.clear();
                    return false;
                }
                
                // Verify these look like original bytes (not hook bytes)
                if (orig_bytes_[0] == 0xE9) {
                    orig_bytes_.clear();
                    return false;
                }
                
                has_original_bytes_ = true;
                return true;
            }
            return false;
        }

        // No hook present, read original bytes directly
        orig_bytes_.resize(size);
        SIZE_T read;
        if (!ReadProcessMemory(h_proc_, target_func_, orig_bytes_.data(), size, &read) || read != size) {
            return false;
        }

        // Verify we didn't read hook bytes
        if (orig_bytes_[0] == 0xE9) {
            orig_bytes_.clear();
            return false;
        }

        has_original_bytes_ = true;
        return true;
    }

    // Restore original bytes with proper page protection
    bool Restore() {
        if (!has_original_bytes_ || orig_bytes_.empty()) {
            return false;
        }

        DWORD old_protect;
        if (!VirtualProtectEx(h_proc_, target_func_, orig_bytes_.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
            return false;
        }

        SIZE_T written;
        bool success = WriteProcessMemory(h_proc_, target_func_, orig_bytes_.data(), orig_bytes_.size(), &written) && written == orig_bytes_.size();
        
        DWORD temp;
        VirtualProtectEx(h_proc_, target_func_, orig_bytes_.size(), old_protect, &temp);
        
        if (!success) {
            return false;
        }

        // Flush instruction cache
        FlushInstructionCache(h_proc_, target_func_, orig_bytes_.size());
        return true;
    }

    // Force restore even if is_installed_ is false (for cleanup on restart)
    bool ForceRestore() {
        if (!has_original_bytes_ || orig_bytes_.empty()) {
            // If hook is present but we don't have original bytes, we can't restore
            // This means a previous installation wasn't cleaned up properly
            return false;
        }
        return Restore();
    }

    // Clean up any existing hook and its allocations (from previous runs)
    bool CleanupExistingHook(size_t hook_size) {
        if (!IsHookPresent(hook_size)) {
            return true; // No hook present, nothing to clean
        }

        // Read the hook to find the trampoline address
        std::vector<BYTE> hook_bytes(6);
        SIZE_T read;
        if (!ReadProcessMemory(h_proc_, target_func_, hook_bytes.data(), 6, &read) || read != 6) {
            return false;
        }
        
        if (hook_bytes[0] != 0xE9) {
            return false; // Not our hook format
        }

        // Calculate trampoline address from relative jump
        DWORD jmp_offset = *(DWORD*)(hook_bytes.data() + 1);
        LPVOID old_trampoline = (LPVOID)((DWORD)target_func_ + 5 + jmp_offset);
        
        // Read original bytes from trampoline (they're at the start)
        std::vector<BYTE> recovered_bytes(hook_size);
        if (ReadProcessMemory(h_proc_, old_trampoline, recovered_bytes.data(), hook_size, &read) && read == hook_size) {
            // Verify these look like original bytes (not hook bytes)
            if (recovered_bytes[0] != 0xE9) {
                orig_bytes_ = recovered_bytes;
                has_original_bytes_ = true;
            }
        }

        // Read trampoline to find helper code address
        // The trampoline has: [ORIG_BYTES][TRAMP_TEMPLATE]
        // In tramp_tmpl, offset 13 has the call instruction (0xE8), offset 14-17 has relative offset
        std::vector<BYTE> tramp_sample(256);
        if (ReadProcessMemory(h_proc_, old_trampoline, tramp_sample.data(), 256, &read) && read >= hook_size + 20) {
            size_t tramp_start = hook_size;
            // Check for call instruction (0xE8) at expected location
            if (tramp_start + 17 < tramp_sample.size() && tramp_sample[tramp_start + 13] == 0xE8) {
                // Calculate helper code address from relative call
                // call instruction format: 0xE8 [4-byte relative offset]
                // Target = call_address + 5 + relative_offset
                DWORD call_offset = *(DWORD*)(tramp_sample.data() + tramp_start + 14);
                DWORD call_from = (DWORD)old_trampoline + tramp_start + 13;
                LPVOID old_helper = (LPVOID)(call_from + 5 + call_offset);
                
                // Verify the helper code looks valid (starts with expected prologue)
                std::vector<BYTE> helper_check(3);
                SIZE_T helper_read;
                if (ReadProcessMemory(h_proc_, old_helper, helper_check.data(), 3, &helper_read) && 
                    helper_read == 3 && 
                    helper_check[0] == 0x55 && helper_check[1] == 0x8B && helper_check[2] == 0xEC) {
                    // This looks like our helper code, free it
                    VirtualFreeEx(h_proc_, old_helper, 0, MEM_RELEASE);
                }
            }
        }

        // Free the old trampoline
        VirtualFreeEx(h_proc_, old_trampoline, 0, MEM_RELEASE);

        // Restore original bytes if we recovered them
        if (has_original_bytes_) {
            Restore();
            Sleep(10); // Small delay to ensure restoration completes
        }

        return true;
    }

    // Force uninstall - always restore, even if is_installed_ is false
    bool ForceUninstall() {
        // First, clean up any existing hooks from previous runs
        CleanupExistingHook(6);

        // Free our allocated memory
        if (trampoline_) {
            VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
            trampoline_ = nullptr;
        }
        if (helper_addr_) {
            VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
            helper_addr_ = nullptr;
        }
        
        // Always try to restore original bytes if we have them
        if (has_original_bytes_) {
            Restore();
        }
        
        is_installed_ = false;
        return true;
    }
};

class SendFunctionHook : public FunctionHook {
private:
    RemoteRingBuffer* rb_;
    static constexpr size_t HOOK_LEN = 8;
    
    // [SHELLCODE] TRAMPOLINE STUB
    const BYTE stub_[64] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // [ORIG] PROLOGUE
        0x60,                                           // pushad
        0x9C,                                           // pushfd
        0x8B, 0x45, 0x0C,                               // mov eax, [ebp+12] (SIZE)
        0x25, 0xFF, 0xFF, 0x00, 0x00,                   // and eax, 0xFFFF
        0x50,                                           // push eax
        0x8B, 0x45, 0x08,                               // mov eax, [ebp+8] (DATA)
        0x50,                                           // push eax
        0x68, 0x00, 0x00, 0x00, 0x00,                   // push RB_ADDR
        0xB8, 0x00, 0x00, 0x00, 0x00,                   // mov eax, HELPER_ADDR
        0xFF, 0xD0,                                     // call eax
        0x83, 0xC4, 0x0C,                               // add esp, 12
        0x9D,                                           // popfd
        0x61,                                           // popad
        0xE9, 0x00, 0x00, 0x00, 0x00                    // jmp ORIG+LEN
    };

public:
    SendFunctionHook(HANDLE h_proc, LPVOID func, RemoteRingBuffer* rb) :
        FunctionHook(h_proc, func), rb_(rb) {}

    bool Install() override;
    bool Uninstall() override;
};

class RecvFunctionHook : public FunctionHook {
private:
    RemoteRingBuffer* rb_;
    static constexpr size_t HOOK_LEN = 5;

    // [SHELLCODE] TRAMPOLINE STUB
    const BYTE stub_[128] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90,             // [ORIG] PROLOGUE
        0x60,                                           // pushad
        0x9C,                                           // pushfd
        0x8B, 0x45, 0x0C,                               // mov eax, [ebp+12]
        0x25, 0xFF, 0xFF, 0xFF, 0xFF,                   // and eax, 0xFFFFFFFF
        0x50,                                           // push eax
        0x8B, 0x45, 0x08,                               // mov eax, [ebp+8]
        0x50,                                           // push eax
        0x68, 0x00, 0x00, 0x00, 0x00,                   // push RB_ADDR
        0xB8, 0x00, 0x00, 0x00, 0x00,                   // mov eax, HELPER_ADDR
        0xFF, 0xD0,                                     // call eax
        0x83, 0xC4, 0x0C,                               // add esp, 12
        0x9D,                                           // popfd
        0x61,                                           // popad
        0xE9, 0x00, 0x00, 0x00, 0x00                    // jmp ORIG+LEN
    };

public:
    RecvFunctionHook(HANDLE h_proc, LPVOID func, RemoteRingBuffer* rb) :
        FunctionHook(h_proc, func), rb_(rb) {}

    bool Install() override;
    bool Uninstall() override;
};

class HookManager {
private:
    HANDLE h_proc_;
    std::unique_ptr<RemoteRingBuffer> rb_send_;
    std::unique_ptr<SendFunctionHook> hk_send_;
    std::unique_ptr<RemoteRingBuffer> rb_recv_;
    std::unique_ptr<RecvFunctionHook> hk_recv_;
    std::thread worker_;
    std::atomic<bool> active_;
    std::mutex cb_lock_;

    void (__stdcall *cb_send_)(const BYTE*, DWORD);
    void (__stdcall *cb_recv_)(const BYTE*, DWORD);

public:
    HookManager(HANDLE h_proc) :
        h_proc_(h_proc), active_(false), cb_send_(nullptr), cb_recv_(nullptr) {}

    ~HookManager() { UninstallAllHooks(); }

    bool InstallAllHooks(void (__stdcall *cb_s)(const BYTE*, DWORD),
                        void (__stdcall *cb_r)(const BYTE*, DWORD));
    
    bool UninstallAllHooks();

    bool InstallSendHook(void (__stdcall *cb)(const BYTE*, DWORD));
    bool UninstallSendHook();
    bool InstallRecvHook(void (__stdcall *cb)(const BYTE*, DWORD));
    bool UninstallRecvHook();

    bool AreHooksInstalled() const {
        return (hk_send_ && hk_send_->IsInstalled()) || (hk_recv_ && hk_recv_->IsInstalled());
    }
};
