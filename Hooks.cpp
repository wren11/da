#include "pch.h"
#include "Hooks.h"
#include "Callbacks/PacketCallbacks.h"

#define LOG(msg) std::cout << "[HOOK] " << msg << std::endl

extern "C" {
    SendPacketCallback_t g_send_callback = nullptr;
    RecvPacketCallback_t g_recv_callback = nullptr;
}

// =========================================================================================
// [ 0x00 ] INJECTED HELPER CODE (NATIVE)
// =========================================================================================
// Purpose: Writes packet data to the ring buffer from within the target process context.
// Architecture: x86 (32-bit)
static const BYTE helper_code[] = {
    // [PROLOGUE]
    0x55, 0x8B, 0xEC,                           // push ebp; mov ebp, esp
    0x53, 0x56, 0x57,                           // push ebx; push esi; push edi

    // [ARGS] [ebp+8]=RB_ADDR, [ebp+12]=DATA, [ebp+16]=SIZE
    0x8B, 0x75, 0x08,                           // mov esi, [ebp+8]
    0x8B, 0x7D, 0x0C,                           // mov edi, [ebp+12] (clobbered later)
    0x8B, 0x5D, 0x10,                           // mov ebx, [ebp+16]

    // [VALIDATION]
    0x85, 0xF6,                                 // test esi, esi
    0x74, 0x39,                                 // jz END
    0x85, 0xFF,                                 // test edi, edi
    0x74, 0x35,                                 // jz END
    0x81, 0xFB, 0xF8, 0x0F, 0x00, 0x00,         // cmp ebx, 4088
    0x77, 0x2D,                                 // ja END

    // [SEQUENCE_CALC]
    0x8B, 0x06,                                 // mov eax, [esi] (write_seq)
    0x8B, 0xD0,                                 // mov edx, eax (save seq)
    0x25, 0xFF, 0x03, 0x00, 0x00,               // and eax, 0x3FF (mod 1024)

    // [ADDR_CALC]
    0x69, 0xC0, 0x00, 0x10, 0x00, 0x00,         // imul eax, eax, 4096
    0x8D, 0x84, 0x06, 0x14, 0x00, 0x00, 0x00,   // lea eax, [esi + eax + 20]

    // [WRITE_SLOT]
    0x89, 0x10,                                 // mov [eax], edx (seq)
    0x89, 0x58, 0x04,                           // mov [eax+4], ebx (size)

    // [COPY_DATA]
    0x8B, 0x75, 0x0C,                           // mov esi, [ebp+12] (src)
    0x8D, 0x78, 0x08,                           // lea edi, [eax+8] (dst)
    0x8B, 0xCB,                                 // mov ecx, ebx (len)
    0xF3, 0xA4,                                 // rep movsb

    // [COMMIT]
    0x83, 0xC2, 0x01,                           // add edx, 1
    0x8B, 0x75, 0x08,                           // mov esi, [ebp+8] (base)
    0x89, 0x16,                                 // mov [esi], edx (update seq)

    // [EPILOGUE]
    0x5F, 0x5E, 0x5B,                           // pop edi; pop esi; pop ebx
    0x8B, 0xE5, 0x5D,                           // mov esp, ebp; pop ebp
    0xC3                                        // ret
};

// =========================================================================================
// [ 0x01 ] TRAMPOLINE TEMPLATE
// =========================================================================================
static const BYTE tramp_tmpl[] = {
    // [CONTEXT_SAVE]
    0x60,                                       // pushad
    0x9C,                                       // pushfd

    // [PREP_CALL]
    0xFF, 0x75, 0x0C,                           // push [ebp+0C] (size)
    0xFF, 0x75, 0x08,                           // push [ebp+08] (data)
    0x68, 0x11, 0x22, 0x33, 0x44,               // push RB_ADDR (PATCH)

    // [CALL_HELPER]
    0xE8, 0xAA, 0xAA, 0xAA, 0xAA,               // call REL32 (PATCH)

    // [STACK_CLEAN]
    0x83, 0xC4, 0x0C,                           // add esp, 12

    // [CONTEXT_RESTORE]
    0x9D,                                       // popfd
    0x61,                                       // popad

    // [RETURN_JMP]
    0xE9, 0x99, 0x99, 0x99, 0x99                // jmp REL32 (PATCH)
};

// =========================================================================================
// [ 0x02 ] SEND HOOK IMPLEMENTATION
// =========================================================================================
bool SendFunctionHook::Install() {
    // Always uninstall first to restore original bytes and clean up any existing hooks
    ForceUninstall();
    
    // Clean up any existing hooks from previous runs (this will free old allocations)
    CleanupExistingHook(6);

    LOG("INSTALLING_SEND_HOOK: 0x" << std::hex << (DWORD)target_func_);

    const size_t STOLEN_SIZE = 6;
    
    // Backup original bytes (will detect and restore existing hooks if present)
    if (!Backup(STOLEN_SIZE)) {
        LOG("FAILED_TO_BACKUP_ORIGINAL_BYTES");
        return false;
    }

    // Allocate helper code
    helper_addr_ = VirtualAllocEx(h_proc_, nullptr, sizeof(helper_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!helper_addr_) {
        LOG("FAILED_TO_ALLOCATE_HELPER_CODE");
        return false;
    }
    
    SIZE_T written;
    if (!WriteProcessMemory(h_proc_, helper_addr_, helper_code, sizeof(helper_code), &written) || written != sizeof(helper_code)) {
        LOG("FAILED_TO_WRITE_HELPER_CODE");
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        helper_addr_ = nullptr;
        return false;
    }

    // Allocate trampoline
    const size_t TRAMP_SIZE = 256;
    trampoline_ = VirtualAllocEx(h_proc_, nullptr, TRAMP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline_) {
        LOG("FAILED_TO_ALLOCATE_TRAMPOLINE");
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        helper_addr_ = nullptr;
        return false;
    }

    std::vector<BYTE> tramp(TRAMP_SIZE, 0x90);
    memcpy(tramp.data(), orig_bytes_.data(), STOLEN_SIZE);
    
    size_t offset = STOLEN_SIZE;
    memcpy(tramp.data() + offset, tramp_tmpl, sizeof(tramp_tmpl));

    // PATCH: RB ADDR
    DWORD rb = (DWORD)rb_->GetBase();
    *(DWORD*)(tramp.data() + offset + 9) = rb;

    // PATCH: CALL HELPER
    DWORD call_from = (DWORD)trampoline_ + offset + 13;
    *(DWORD*)(tramp.data() + offset + 14) = (DWORD)helper_addr_ - (call_from + 5);

    // PATCH: JMP BACK
    DWORD jmp_from = (DWORD)trampoline_ + offset + 23;
    DWORD ret_addr = (DWORD)target_func_ + STOLEN_SIZE;
    *(DWORD*)(tramp.data() + offset + 24) = ret_addr - (jmp_from + 5);

    if (!WriteProcessMemory(h_proc_, trampoline_, tramp.data(), TRAMP_SIZE, &written) || written != TRAMP_SIZE) {
        LOG("FAILED_TO_WRITE_TRAMPOLINE");
        VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        trampoline_ = helper_addr_ = nullptr;
        return false;
    }

    // APPLY HOOK with proper page protection
    std::vector<BYTE> hook(STOLEN_SIZE, 0x90);
    hook[0] = 0xE9;
    *(DWORD*)(&hook[1]) = (DWORD)trampoline_ - ((DWORD)target_func_ + 5);

    DWORD old_protect;
    if (!VirtualProtectEx(h_proc_, target_func_, STOLEN_SIZE, PAGE_EXECUTE_READWRITE, &old_protect)) {
        LOG("FAILED_TO_CHANGE_PAGE_PROTECTION_FOR_HOOK");
        VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        trampoline_ = helper_addr_ = nullptr;
        return false;
    }

    if (!WriteProcessMemory(h_proc_, target_func_, hook.data(), STOLEN_SIZE, &written) || written != STOLEN_SIZE) {
        LOG("FAILED_TO_WRITE_HOOK");
        DWORD temp;
        VirtualProtectEx(h_proc_, target_func_, STOLEN_SIZE, old_protect, &temp);
        VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        trampoline_ = helper_addr_ = nullptr;
        return false;
    }

    DWORD temp;
    VirtualProtectEx(h_proc_, target_func_, STOLEN_SIZE, old_protect, &temp);
    FlushInstructionCache(h_proc_, target_func_, STOLEN_SIZE);

    is_installed_ = true;
    LOG("SEND_HOOK_ACTIVE");
    return true;
}

bool SendFunctionHook::Uninstall() {
    if (!is_installed_) {
        // Nothing to uninstall
        return true;
    }
    
    LOG("REMOVING_SEND_HOOK");
    
    // Restore original bytes
    if (!Restore()) {
        LOG("WARNING: Failed to restore original bytes");
    }
    
    // Free allocated memory
    if (trampoline_) {
        VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
        trampoline_ = nullptr;
    }
    if (helper_addr_) {
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        helper_addr_ = nullptr;
    }
    
    is_installed_ = false;
    LOG("SEND_HOOK_REMOVED");
    return true;
}

// =========================================================================================
// [ 0x03 ] RECV HOOK IMPLEMENTATION
// =========================================================================================
bool RecvFunctionHook::Install() {
    // Always uninstall first to restore original bytes and clean up any existing hooks
    ForceUninstall();
    
    // Clean up any existing hooks from previous runs (this will free old allocations)
    CleanupExistingHook(6);

    LOG("INSTALLING_RECV_HOOK: 0x" << std::hex << (DWORD)target_func_);

    const size_t STOLEN_SIZE = 6;
    
    // Backup original bytes (will detect and restore existing hooks if present)
    if (!Backup(STOLEN_SIZE)) {
        LOG("FAILED_TO_BACKUP_ORIGINAL_BYTES");
        return false;
    }

    // Allocate helper code
    helper_addr_ = VirtualAllocEx(h_proc_, nullptr, sizeof(helper_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!helper_addr_) {
        LOG("FAILED_TO_ALLOCATE_HELPER_CODE");
        return false;
    }
    
    SIZE_T written;
    if (!WriteProcessMemory(h_proc_, helper_addr_, helper_code, sizeof(helper_code), &written) || written != sizeof(helper_code)) {
        LOG("FAILED_TO_WRITE_HELPER_CODE");
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        helper_addr_ = nullptr;
        return false;
    }

    // Allocate trampoline
    trampoline_ = VirtualAllocEx(h_proc_, nullptr, 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline_) {
        LOG("FAILED_TO_ALLOCATE_TRAMPOLINE");
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        helper_addr_ = nullptr;
        return false;
    }

    std::vector<BYTE> tramp(256, 0xCC);
    memcpy(tramp.data(), orig_bytes_.data(), STOLEN_SIZE);
    memcpy(tramp.data() + STOLEN_SIZE, tramp_tmpl, sizeof(tramp_tmpl));

    DWORD rb = (DWORD)rb_->GetBase();
    *(DWORD*)(tramp.data() + STOLEN_SIZE + 9) = rb;

    DWORD call_from = (DWORD)trampoline_ + STOLEN_SIZE + 13;
    *(DWORD*)(tramp.data() + STOLEN_SIZE + 14) = (DWORD)helper_addr_ - (call_from + 5);

    DWORD jmp_from = (DWORD)trampoline_ + STOLEN_SIZE + 23;
    DWORD ret_addr = (DWORD)target_func_ + STOLEN_SIZE;
    *(DWORD*)(tramp.data() + STOLEN_SIZE + 24) = ret_addr - (jmp_from + 5);

    if (!WriteProcessMemory(h_proc_, trampoline_, tramp.data(), 256, &written) || written != 256) {
        LOG("FAILED_TO_WRITE_TRAMPOLINE");
        VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        trampoline_ = helper_addr_ = nullptr;
        return false;
    }

    // APPLY HOOK with proper page protection
    BYTE hook[6] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90 };
    *(DWORD*)(hook + 1) = (DWORD)trampoline_ - ((DWORD)target_func_ + 5);

    DWORD old_protect;
    if (!VirtualProtectEx(h_proc_, target_func_, STOLEN_SIZE, PAGE_EXECUTE_READWRITE, &old_protect)) {
        LOG("FAILED_TO_CHANGE_PAGE_PROTECTION_FOR_HOOK");
        VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        trampoline_ = helper_addr_ = nullptr;
        return false;
    }

    if (!WriteProcessMemory(h_proc_, target_func_, hook, 6, &written) || written != 6) {
        LOG("FAILED_TO_WRITE_HOOK");
        DWORD temp;
        VirtualProtectEx(h_proc_, target_func_, STOLEN_SIZE, old_protect, &temp);
        VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        trampoline_ = helper_addr_ = nullptr;
        return false;
    }

    DWORD temp;
    VirtualProtectEx(h_proc_, target_func_, STOLEN_SIZE, old_protect, &temp);
    FlushInstructionCache(h_proc_, target_func_, STOLEN_SIZE);

    is_installed_ = true;
    LOG("RECV_HOOK_ACTIVE");
    return true;
}

bool RecvFunctionHook::Uninstall() {
    if (!is_installed_) {
        // Nothing to uninstall
        return true;
    }
    
    LOG("REMOVING_RECV_HOOK");
    
    // Restore original bytes
    if (!Restore()) {
        LOG("WARNING: Failed to restore original bytes");
    }
    
    // Free allocated memory
    if (trampoline_) {
        VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
        trampoline_ = nullptr;
    }
    if (helper_addr_) {
        VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
        helper_addr_ = nullptr;
    }
    
    is_installed_ = false;
    LOG("RECV_HOOK_REMOVED");
    return true;
}

// =========================================================================================
// [ 0x04 ] HOOK MANAGER IMPLEMENTATION
// =========================================================================================
bool HookManager::InstallAllHooks(void (__stdcall *cb_s)(const BYTE*, DWORD), void (__stdcall *cb_r)(const BYTE*, DWORD)) {
    LOG("INSTALLING_ALL_HOOKS - cleaning up any existing state");
    
    // Always uninstall all hooks first to ensure clean state
    // This will:
    // 1. Stop worker thread
    // 2. Restore original bytes
    // 3. Free all trampolines and helper code
    // 4. Free all ring buffers
    UninstallAllHooks();
    
    // Small delay to ensure cleanup completes
    Sleep(50);
    
    if (!InstallSendHook(cb_s)) {
        LOG("FAILED_TO_INSTALL_SEND_HOOK");
        return false;
    }
    if (!InstallRecvHook(cb_r)) {
        LOG("FAILED_TO_INSTALL_RECV_HOOK - cleaning up");
        UninstallSendHook();
        return false;
    }
    
    LOG("ALL_HOOKS_INSTALLED_SUCCESSFULLY");
    return true;
}

bool HookManager::UninstallAllHooks() {
    LOG("UNINSTALLING_ALL_HOOKS - complete cleanup");
    
    // Stop worker thread first to prevent race conditions
    active_ = false;
    if (worker_.joinable()) {
        worker_.join();
    }
    
    // Uninstall hooks (this will restore original bytes and free allocations)
    UninstallSendHook();
    UninstallRecvHook();
    
    // Ensure everything is cleaned up
    // Reset all pointers to ensure no stale references
    hk_send_.reset();
    hk_recv_.reset();
    rb_send_.reset();
    rb_recv_.reset();
    
    LOG("ALL_HOOKS_UNINSTALLED - state is clean");
    return true;
}

bool HookManager::InstallSendHook(void (__stdcall *cb)(const BYTE*, DWORD)) {
    try {
        // Clean up any existing hook first
        if (hk_send_) {
            hk_send_->Uninstall();
            hk_send_.reset();
        }
        if (rb_send_) {
            rb_send_.reset();
        }

        rb_send_ = std::make_unique<RemoteRingBuffer>(h_proc_);
        hk_send_ = std::make_unique<SendFunctionHook>(h_proc_, (LPVOID)0x00563E00, rb_send_.get());

        if (!hk_send_->Install()) {
            LOG("FAILED_TO_INSTALL_SEND_HOOK");
            hk_send_.reset();
            rb_send_.reset();
            return false;
        }

        cb_send_ = cb;
        
        // Start worker thread if not already running
        if (!active_) {
            active_ = true;
            worker_ = std::thread([this]() {
                std::vector<BYTE> buf;
                while (active_) {
                    bool busy = false;
                    if (rb_send_ && rb_send_->ReadPacket(buf)) {
                        std::lock_guard<std::mutex> lock(cb_lock_);
                        if (cb_send_) cb_send_(buf.data(), (DWORD)buf.size());
                        busy = true;
                    }
                    if (rb_recv_ && rb_recv_->ReadPacket(buf)) {
                        std::lock_guard<std::mutex> lock(cb_lock_);
                        if (cb_recv_) cb_recv_(buf.data(), (DWORD)buf.size());
                        busy = true;
                    }
                    if (!busy) Sleep(1);
                }
            });
        }
        return true;
    } catch (...) {
        LOG("EXCEPTION_IN_INSTALL_SEND_HOOK");
        if (hk_send_) hk_send_.reset();
        if (rb_send_) rb_send_.reset();
        return false;
    }
}

bool HookManager::UninstallSendHook() {
    cb_send_ = nullptr;
    
    if (hk_send_) {
        hk_send_->Uninstall();
        hk_send_.reset();
    }
    
    if (rb_send_) {
        rb_send_.reset();
    }
    
    // Stop worker thread if no hooks are installed
    if (!hk_send_ && !hk_recv_) {
        active_ = false;
        if (worker_.joinable()) {
            worker_.join();
        }
    }
    
    return true;
}

bool HookManager::InstallRecvHook(void (__stdcall *cb)(const BYTE*, DWORD)) {
    try {
        // Clean up any existing hook first
        if (hk_recv_) {
            hk_recv_->Uninstall();
            hk_recv_.reset();
        }
        if (rb_recv_) {
            rb_recv_.reset();
        }

        rb_recv_ = std::make_unique<RemoteRingBuffer>(h_proc_);
        hk_recv_ = std::make_unique<RecvFunctionHook>(h_proc_, (LPVOID)0x00467060, rb_recv_.get()); // RECV_FUNC_ADDR
        
        if (!hk_recv_->Install()) {
            LOG("FAILED_TO_INSTALL_RECV_HOOK");
            hk_recv_.reset();
            rb_recv_.reset();
            return false;
        }
        
        cb_recv_ = cb;
        
        // Start worker thread if not already running
        if (!active_) {
            active_ = true;
            worker_ = std::thread([this]() {
                std::vector<BYTE> buf;
                while (active_) {
                    bool busy = false;
                    if (rb_send_ && rb_send_->ReadPacket(buf)) {
                        std::lock_guard<std::mutex> lock(cb_lock_);
                        if (cb_send_) cb_send_(buf.data(), (DWORD)buf.size());
                        busy = true;
                    }
                    if (rb_recv_ && rb_recv_->ReadPacket(buf)) {
                        std::lock_guard<std::mutex> lock(cb_lock_);
                        if (cb_recv_) cb_recv_(buf.data(), (DWORD)buf.size());
                        busy = true;
                    }
                    if (!busy) Sleep(1);
                }
            });
        }
        
        return true;
    } catch (...) {
        LOG("EXCEPTION_IN_INSTALL_RECV_HOOK");
        if (hk_recv_) hk_recv_.reset();
        if (rb_recv_) rb_recv_.reset();
        return false;
    }
}

bool HookManager::UninstallRecvHook() {
    cb_recv_ = nullptr;
    
    if (hk_recv_) {
        hk_recv_->Uninstall();
        hk_recv_.reset();
    }
    
    if (rb_recv_) {
        rb_recv_.reset();
    }

    // Stop worker thread if no hooks are installed
    if (!hk_send_ && !hk_recv_) {
        active_ = false;
        if (worker_.joinable()) {
            worker_.join();
        }
    }
    
    return true;
}
