#pragma once
#include "pch.h"
#include "Core/IMemoryManager.h"

namespace DarkAges {
    namespace Core {
        class IGameBot {
        public:
            virtual ~IGameBot() = default;
            virtual bool Initialize() = 0;
            virtual void Shutdown() = 0;
            virtual void Update() = 0;
            virtual bool IsRunning() const = 0;
            virtual IProcess& GetProcess() = 0;
        };
    }
}