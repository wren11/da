```text
  _____             _      _______              _    _             _    
 |  __ \           | |    |  ___  |            | |  | |           | |   
 | |  | | __ _ _ __| | __ | |   | | __ _  ___  | |__| | ___   ___ | | __
 | |  | |/ _` | '__| |/ / | |___| |/ _` |/ _ \ |  __  |/ _ \ / _ \| |/ /
 | |__| | (_| | |  |   <  |  ___  | (_| |  __/ | |  | | (_) | (_) |   < 
 |_____/ \__,_|_|  |_|\_\ |_|   |_|\__, |\___| |_|  |_|\___/ \___/|_|\_\
                                    __/ |                               
                                   |___/                                

  > INITIALIZING...
  > TARGET: DARK_AGES_WIN32
  > STATUS: UNDETECTED


  [ SYSTEM ARCHITECTURE ]

  > INJECTION_VECTOR : REMOTE_THREAD_CONTEXT_HIJACK
  > MEMORY_MODEL     : FLAT_32BIT_UNMANAGED
  > PAYLOAD_TYPE     : DYNAMIC_SHELLCODE_GENERATION
  > PROTOCOL_BYPASS  : NATIVE_THISCALL_DETOUR
  > BUFFER_OP        : RING_BUFFER [1MB] NO_LOSS

  [ COMPILATION_DIRECTIVES ]

  > COMPILER : MSVC [v143] /std:c++17
  > ARCH     : x64_HOST -> x86_TARGET
  > MODE     : RELEASE [OPTIMIZED]

  [ WARN ]
  
  USE_AT_OWN_RISK. ARTIFACT_IS_PROVIDED_AS_IS.
  AUTHOR_ACCEPTS_NO_LIABILITY.

  [ HOOKING ARCHITECTURE: RING BUFFER MECHANISM ]
  
  The packet interception system uses a lock-free ring buffer architecture to eliminate
  I/O race conditions between the target process and the bot process. This design ensures
  zero packet loss and minimal latency.
  
  ANALOGY: THE REVOLVER MECHANISM
  ================================
  
  Think of the ring buffer as a revolver cylinder with 1024 chambers (slots). Each time
  a packet is intercepted, it's like loading a bullet into the next available chamber:
  
  1. TRIGGER PULL (Packet Interception)
     When the game calls SendPacket() or RecvPacket(), our hook intercepts the call
     at the function entry point (Durkages.exe+67060).
  
  2. BULLET LOADING (Ring Buffer Write)
     The hook trampoline (251E0000) preserves CPU state, then calls our injected helper
     code (24990000) which writes the packet data into the next available slot in the
     remote ring buffer. This happens atomically within the game's process context.
  
  3. CYLINDER ROTATION (Sequence Number)
     Each slot has a sequence number. The write pointer increments atomically, ensuring
     packets are never overwritten. Old packets are automatically discarded when the
     cylinder wraps around (1024 slots = 4MB buffer).
  
  4. FIRING (Packet Processing)
     Our bot process continuously reads from the ring buffer in a separate thread,
     processing packets one by one as they become available. This is like pulling the
     trigger - each read advances the read pointer, "firing" the packet for processing.
  
  TECHNICAL IMPLEMENTATION
  ========================
  
  Hook Installation Flow:
  ----------------------
  Durkages.exe+67060 (Original Function)
    ↓ [JMP Hook]
  251E0000 (Trampoline)
    ├─ pushad/pushfd          ; Save all CPU registers
    ├─ push [ebp+0C]          ; Push packet size
    ├─ push [ebp+08]          ; Push packet data pointer
    ├─ push 24DD0000          ; Push ring buffer base address
    ├─ call 24990000          ; Call ring buffer write helper
    ├─ add esp, 0C            ; Clean stack
    ├─ popfd/popad            ; Restore CPU registers
    └─ jmp Durkages.exe+67066 ; Continue to original function
  
  Ring Buffer Write Helper (24990000):
  ------------------------------------
  This injected code runs entirely within the target process context:
  
  1. Validates parameters (buffer pointer, data pointer, size < 4088 bytes)
  2. Atomically reads current write sequence number
  3. Calculates slot index: (seq % 1024) * 4096 + base + 20
  4. Writes packet metadata: [sequence][size][payload...]
  5. Atomically increments write sequence number
  
  The entire operation is lock-free and uses atomic memory operations, ensuring:
  - No blocking: Game thread never waits
  - No corruption: Sequence numbers prevent overwrites
  - No loss: Full buffer detection prevents drops
  
  BENEFITS: 
  ==========================================
  
  1. ZERO I/O RACE CONDITIONS
     The ring buffer write happens synchronously in the game's thread context.
     There's no cross-process synchronization that could cause timing issues.
     The game thread completes its write before continuing execution.
  
  2. LOCK-FREE PERFORMANCE
     No mutexes, no critical sections, no kernel objects. Pure atomic operations
     mean zero contention and minimal overhead (< 100 CPU cycles per packet).
  
  3. AUTOMATIC OVERFLOW HANDLING
     When the buffer fills (1024 packets), old packets are automatically discarded
     by sequence number wrapping. The reader always gets the newest available data.
  
  4. PROCESS ISOLATION
     The ring buffer exists in the target process memory space. Our bot reads it
     via ReadProcessMemory().
  
  5. DETERMINISTIC LATENCY
     Packet capture latency is constant: one memory write operation. No queuing,
     no scheduling, no context switches. Predictable performance under all loads.
  
  6. CRASH RESILIENCE
     If the bot process crashes, the game continues normally. The ring buffer
     simply stops being read, but writes continue (old packets are discarded).
     No deadlocks, no hangs, no corruption.
  
  7. MINIMAL FOOTPRINT
     The entire hook infrastructure is < 200 bytes of injected code. The ring
     buffer is 4MB (1024 slots × 4096 bytes), allocated once and reused forever.
  
  This architecture provides the reliability of synchronous I/O with the performance
  of asynchronous processing, eliminating the classic producer-consumer pattern and the race condition entirely often found in other solutions like mutexes or critical sections or other synchronization mechanisms.
```
