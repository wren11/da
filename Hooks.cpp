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
    if (is_installed_) return true;

    LOG("INSTALLING_SEND_HOOK: 0x" << std::hex << (DWORD)target_func_);

    BYTE byte;
    if (!ReadProcessMemory(h_proc_, target_func_, &byte, 1, nullptr)) return false;
    if (byte == 0xE9 || byte == 0xE8) {
        LOG("TARGET_ALREADY_HOOKED");
        return false;
    }

    const size_t STOLEN_SIZE = 6;
    if (!Backup(STOLEN_SIZE)) return false;

    helper_addr_ = VirtualAllocEx(h_proc_, nullptr, sizeof(helper_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!helper_addr_) return false;
    WriteProcessMemory(h_proc_, helper_addr_, helper_code, sizeof(helper_code), nullptr);

    const size_t TRAMP_SIZE = 256;
    trampoline_ = VirtualAllocEx(h_proc_, nullptr, TRAMP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline_) return false;

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

    if (!WriteProcessMemory(h_proc_, trampoline_, tramp.data(), TRAMP_SIZE, nullptr)) return false;

    // APPLY HOOK
    std::vector<BYTE> hook(STOLEN_SIZE, 0x90);
    hook[0] = 0xE9;
    *(DWORD*)(&hook[1]) = (DWORD)trampoline_ - ((DWORD)target_func_ + 5);

    if (!WriteProcessMemory(h_proc_, target_func_, hook.data(), STOLEN_SIZE, nullptr)) return false;

    is_installed_ = true;
    LOG("SEND_HOOK_ACTIVE");
    return true;
}

bool SendFunctionHook::Uninstall() {
    if (!is_installed_) return true;
    LOG("REMOVING_SEND_HOOK");
    Restore();
    if (trampoline_) VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
    if (helper_addr_) VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
    trampoline_ = helper_addr_ = nullptr;
    is_installed_ = false;
    return true;
}

// =========================================================================================
// [ 0x03 ] RECV HOOK IMPLEMENTATION
// =========================================================================================
bool RecvFunctionHook::Install() {
    if (is_installed_) return true;

    LOG("INSTALLING_RECV_HOOK: 0x" << std::hex << (DWORD)target_func_);

    BYTE byte;
    if (!ReadProcessMemory(h_proc_, target_func_, &byte, 1, nullptr)) return false;
    if (byte == 0xE9 || byte == 0xE8) {
        LOG("TARGET_ALREADY_HOOKED");
        return false;
    }

    const size_t STOLEN_SIZE = 6;
    if (!Backup(STOLEN_SIZE)) return false;

    helper_addr_ = VirtualAllocEx(h_proc_, nullptr, sizeof(helper_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!helper_addr_) return false;
    WriteProcessMemory(h_proc_, helper_addr_, helper_code, sizeof(helper_code), nullptr);

    trampoline_ = VirtualAllocEx(h_proc_, nullptr, 256, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline_) return false;

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

    WriteProcessMemory(h_proc_, trampoline_, tramp.data(), 256, nullptr);

    BYTE hook[6] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90 };
    *(DWORD*)(hook + 1) = (DWORD)trampoline_ - ((DWORD)target_func_ + 5);
    WriteProcessMemory(h_proc_, target_func_, hook, 6, nullptr);

    is_installed_ = true;
    LOG("RECV_HOOK_ACTIVE");
    return true;
}

bool RecvFunctionHook::Uninstall() {
    if (!is_installed_) return true;
    LOG("REMOVING_RECV_HOOK");
    Restore();
    if (trampoline_) VirtualFreeEx(h_proc_, trampoline_, 0, MEM_RELEASE);
    if (helper_addr_) VirtualFreeEx(h_proc_, helper_addr_, 0, MEM_RELEASE);
    trampoline_ = helper_addr_ = nullptr;
    is_installed_ = false;
    return true;
}

// =========================================================================================
// [ 0x04 ] HOOK MANAGER IMPLEMENTATION
// =========================================================================================
bool HookManager::InstallAllHooks(void (__stdcall *cb_s)(const BYTE*, DWORD), void (__stdcall *cb_r)(const BYTE*, DWORD)) {
    if (!InstallSendHook(cb_s)) return false;
    if (!InstallRecvHook(cb_r)) {
        UninstallSendHook();
        return false;
    }
    return true;
}

bool HookManager::UninstallAllHooks() {
    UninstallSendHook();
    UninstallRecvHook();
    return true;
}

bool HookManager::InstallSendHook(void (__stdcall *cb)(const BYTE*, DWORD)) {
    try {
        rb_send_ = std::make_unique<RemoteRingBuffer>(h_proc_);
        hk_send_ = std::make_unique<SendFunctionHook>(h_proc_, (LPVOID)0x00563E00, rb_send_.get());

        if (!hk_send_->Install()) {
            rb_send_.reset();
            return false;
        }

        cb_send_ = cb;
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
        return false;
    }
}

bool HookManager::UninstallSendHook() {
    cb_send_ = nullptr;
    if (hk_send_) hk_send_->Uninstall();
    hk_send_.reset();
    rb_send_.reset();
    
    if (!hk_send_ && !hk_recv_) {
        active_ = false;
        if (worker_.joinable()) worker_.join();
    }
    return true;
}

bool HookManager::InstallRecvHook(void (__stdcall *cb)(const BYTE*, DWORD)) {
    try {
        rb_recv_ = std::make_unique<RemoteRingBuffer>(h_proc_);
        hk_recv_ = std::make_unique<RecvFunctionHook>(h_proc_, (LPVOID)0x00467060, rb_recv_.get()); // RECV_FUNC_ADDR
        if (!hk_recv_->Install()) {
            rb_recv_.reset();
            return false;
        }
        cb_recv_ = cb;
        return true;
    } catch (...) {
        return false;
    }
}

bool HookManager::UninstallRecvHook() {
    cb_recv_ = nullptr;
    if (hk_recv_) hk_recv_->Uninstall();
    hk_recv_.reset();
    rb_recv_.reset();

    if (!hk_send_ && !hk_recv_) {
        active_ = false;
        if (worker_.joinable()) worker_.join();
    }
    return true;
}
