#pragma once
#include "pch.h"

namespace DarkAges {
    namespace Core {
        class IMemoryManager {
        public:
            virtual ~IMemoryManager() = default;
            virtual LPVOID Allocate(size_t size) = 0;
            virtual bool Deallocate(LPVOID ptr) = 0;
            virtual bool Write(LPVOID addr, const void* data, size_t size) = 0;
            virtual bool Read(LPVOID addr, void* buffer, size_t size) = 0;
            virtual LPVOID ReadPointer(LPVOID addr) = 0;
            virtual void CollectGarbage() = 0;
        };
        class IProcess {
        public:
            virtual ~IProcess() = default;
            virtual HANDLE GetHandle() const = 0;
            virtual LPVOID GetBaseAddress() const = 0;
            virtual bool IsAttached() const = 0;
            virtual void Attach() = 0;
            virtual void Detach() = 0;
            virtual IMemoryManager& GetMemoryManager() = 0;
        };
        class IBuffer {
        public:
            virtual ~IBuffer() = default;
            virtual bool Write(const BYTE* data, DWORD size) = 0;
            virtual bool Read(std::vector<BYTE>& out) = 0;
        };
        class IOperation {
        public:
            virtual ~IOperation() = default;
            virtual bool Execute() = 0;
            virtual std::string GetName() const = 0;
        };
    }
}