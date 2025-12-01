#include "pch.h"
#include "Bot/GameBot.h"
#include "Operations/WalkOperation.h"
#include "Operations/LoginOperation.h"
#include "Operations/PacketOperation.h"
#include "Operations/GameConstants.h"

namespace DarkAges {
    namespace Bot {

        static bool SendBufferWriteWrapper(void* buffer, const BYTE* data, DWORD size) {
            if (!buffer) return false;
            auto* rb = static_cast<Memory::RingBuffer*>(buffer);
            return rb->Write(data, size);
        }

        static bool RecvBufferWriteWrapper(void* buffer, const BYTE* data, DWORD size) {
            if (!buffer) return false;
            auto* rb = static_cast<Memory::RingBuffer*>(buffer);
            return rb->Write(data, size);
        }

        GameBot::GameBot() : running_(false), silent_mode_(false), serial_id_(0),
            active_flood_(false), active_walk_(false), active_hooks_(false) {
            config_ = std::make_unique<Config::Configuration>();
        }

        GameBot::~GameBot() { Shutdown(); }

        bool GameBot::Initialize() {
            DWORD pid = 0;
            if (!FindProcess(L"Durkages.exe", pid)) {
                std::cout << "[ERROR] Target process not found\n";
                return false;
            }
            try {
                process_ = std::make_unique<Memory::Process>(pid);
                process_->Attach();
                std::cout << "[SYSTEM] Attached to process. Base: 0x"
                    << std::hex << reinterpret_cast<DWORD>(process_->GetBaseAddress()) << std::dec << "\n";
                InitializeCallbacks();
                config_->Load();
                running_.store(true);
                return true;
            }
            catch (const std::exception& e) {
                std::cout << "[ERROR] Initialization failed: " << e.what() << "\n";
                return false;
            }
        }

        void GameBot::Shutdown() {
            if (!running_.load()) return;
            running_.store(false);
            if (active_hooks_) process_->UninstallHooks();
            CleanupPacketCallbacks();
            if (process_) process_->Detach();
        }

        void GameBot::Update() {
            if (!running_.load()) return;
            ProcessInput();
            UpdateOperations();
            auto& mm = static_cast<Memory::MemoryManager&>(process_->GetMemoryManager());
            mm.CollectGarbage();
            Sleep(10);
        }

        bool GameBot::FindProcess(const std::wstring& process_name, DWORD& pid) {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE) return false;
            PROCESSENTRY32W entry;
            entry.dwSize = sizeof(PROCESSENTRY32W);
            bool found = false;
            if (Process32FirstW(snapshot, &entry)) {
                do {
                    if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) {
                        pid = entry.th32ProcessID;
                        found = true;
                        break;
                    }
                } while (Process32NextW(snapshot, &entry));
            }
            CloseHandle(snapshot);
            return found;
        }

        void GameBot::InitializeCallbacks() {
            PacketCallbackContext ctx;
            ctx.send_buffer = &process_->GetSendBuffer();
            ctx.recv_buffer = &process_->GetRecvBuffer();
            ctx.silent_mode = &silent_mode_;
            ctx.serial_id = &serial_id_;
            ctx.player_name = &player_name_;
            ctx.callback_lock = &callback_lock_;
            ctx.send_buffer_write = SendBufferWriteWrapper;
            ctx.recv_buffer_write = RecvBufferWriteWrapper;
            InitializePacketCallbacks(ctx);
        }

        void GameBot::ProcessInput() {
            if (!_kbhit()) return;
            int key = _getch();
            switch (key) {
            case 'q': running_.store(false); break;
            case '1': case '2': case '3': case '4': case '5':
            case '6': case '7': case '8': case '9':
                ExecuteLogin(key - '1'); break;
            case 'm': ExecuteLoginAll(); break;
            case 'h': ToggleHooks(); break;
            case 'd': SetSilentMode(!GetSilentMode());
                std::cout << "[SYS] Silent mode: " << (GetSilentMode() ? "ON" : "OFF") << "\n"; break;
            case 't': ToggleFlood(); break;
            case 'w': ToggleWalk(); break;
            }
        }

        void GameBot::UpdateOperations() {
            auto now = std::chrono::steady_clock::now();
            if (active_flood_) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_send_time_).count();
                if (elapsed > 1000) {
                    Operations::PacketOperation op(process_->GetMemoryManager(), { 0x38, 0x01, 0x00 });
                    op.Execute();
                    last_send_time_ = now;
                }
            }
            if (active_walk_) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_walk_time_).count();
                if (elapsed > Operations::GameConstants::INTERVAL_WALK_MS) {
                    Operations::WalkOperation op(process_->GetMemoryManager(), 1);
                    op.Execute();
                    last_walk_time_ = now;
                }
            }
        }

        void GameBot::ExecuteLogin(size_t account_index) {
            const auto& accounts = config_->GetAccounts();
            if (account_index >= accounts.size()) {
                std::cout << "[ERROR] Invalid account index\n";
                return;
            }
            const auto& cred = accounts[account_index];
            player_name_ = cred.username;
            Operations::LoginOperation op(process_->GetMemoryManager(), cred.username, cred.password);
            if (op.Execute()) {
                std::cout << "[AUTH] Login sequence completed for: " << cred.username << "\n";
            }
        }

        void GameBot::ExecuteLoginAll() {
            const auto& accounts = config_->GetAccounts();
            for (const auto& cred : accounts) {
                Operations::LoginOperation op(process_->GetMemoryManager(), cred.username, cred.password);
                op.Execute();
                Sleep(1000);
            }
        }

        void GameBot::ToggleHooks() {
            active_hooks_ = !active_hooks_;
            if (active_hooks_) {
                InitializeCallbacks();
                process_->InstallHooks(SendPacketCallback, RecvPacketCallback);
            }
            else {
                process_->UninstallHooks();
            }
            std::cout << "[SYS] Hooks: " << (active_hooks_ ? "ENABLED" : "DISABLED") << "\n";
        }

        void GameBot::ToggleFlood() {
            active_flood_ = !active_flood_;
            std::cout << "[SYS] Flood: " << (active_flood_ ? "ON" : "OFF") << "\n";
        }

        void GameBot::ToggleWalk() {
            active_walk_ = !active_walk_;
            std::cout << "[SYS] Walk: " << (active_walk_ ? "ON" : "OFF") << "\n";
        }

        void GameBot::PrintMenu() const {
            std::cout << "\n[ OPERATIONS MENU ]\n";
            const auto& accounts = config_->GetAccounts();
            for (size_t i = 0; i < accounts.size() && i < 9; ++i) {
                std::cout << "  " << (i + 1) << " : Login [" << accounts[i].username << "]\n";
            }
            std::cout << "  M : Login All\n";
            std::cout << "  T : Toggle Packet Flood\n";
            std::cout << "  W : Toggle Auto Walk\n";
            std::cout << "  H : Toggle Hooks\n";
            std::cout << "  D : Toggle Silent Mode\n";
            std::cout << "  Q : Quit\n";
            std::cout << "\n> ";
        }
    }
}