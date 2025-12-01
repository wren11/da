#pragma once
#include "pch.h"
#include "Core/IGameBot.h"
#include "Memory/Process.h"
#include "Config/Configuration.h"
#include "Operations/IOperation.h"
#include "Callbacks/PacketCallbacks.h"

namespace DarkAges {
    namespace Bot {

        class GameBot : public Core::IGameBot {
        private:
            std::unique_ptr<Memory::Process> process_;
            std::unique_ptr<Config::Configuration> config_;
            std::atomic<bool> running_;
            std::atomic<bool> silent_mode_;
            std::atomic<DWORD> serial_id_;
            std::string player_name_;
            std::mutex callback_lock_;
            std::chrono::steady_clock::time_point last_walk_time_;
            std::chrono::steady_clock::time_point last_send_time_;
            bool active_flood_;
            bool active_walk_;
            bool active_hooks_;
            bool FindProcess(const std::wstring& process_name, DWORD& pid);
            void InitializeCallbacks();
            void ProcessInput();
            void UpdateOperations();
        public:
            GameBot();
            ~GameBot() override;
            bool Initialize() override;
            void Shutdown() override;
            void Update() override;
            bool IsRunning() const override { return running_.load(); }
            Core::IProcess& GetProcess() override { return *process_; }
            void SetSilentMode(bool enabled) { silent_mode_.store(enabled); }
            bool GetSilentMode() const { return silent_mode_.load(); }
            void ExecuteLogin(size_t account_index);
            void ExecuteLoginAll();
            void ToggleHooks();
            void ToggleFlood();
            void ToggleWalk();
            void PrintMenu() const;
        };
    }
}