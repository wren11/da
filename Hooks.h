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
    std::vector<BYTE> orig_bytes_;
    bool is_installed_;

public:
    FunctionHook(HANDLE h_proc, LPVOID target) :
        h_proc_(h_proc), target_func_(target), trampoline_(nullptr), is_installed_(false) {}

    virtual ~FunctionHook() { if (is_installed_) Uninstall(); }
    virtual bool Install() = 0;
    virtual bool Uninstall() { return false; }
    bool IsInstalled() const { return is_installed_; }

protected:
    bool Backup(size_t size) {
        orig_bytes_.resize(size);
        SIZE_T read;
        return ReadProcessMemory(h_proc_, target_func_, orig_bytes_.data(), size, &read) && read == size;
    }

    bool Restore() {
        if (orig_bytes_.empty()) return false;
        SIZE_T written;
        return WriteProcessMemory(h_proc_, target_func_, orig_bytes_.data(), orig_bytes_.size(), &written) && written == orig_bytes_.size();
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
    
    LPVOID helper_addr_;

public:
    SendFunctionHook(HANDLE h_proc, LPVOID func, RemoteRingBuffer* rb) :
        FunctionHook(h_proc, func), rb_(rb), helper_addr_(nullptr) {}

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

    LPVOID helper_addr_;

public:
    RecvFunctionHook(HANDLE h_proc, LPVOID func, RemoteRingBuffer* rb) :
        FunctionHook(h_proc, func), rb_(rb), helper_addr_(nullptr) {}

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
