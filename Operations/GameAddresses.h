#pragma once
#include "pch.h"

namespace DarkAges {
    namespace Operations {
        struct GameAddresses {
            static constexpr DWORD OBJECT_BASE = 0x00882E68;
            static constexpr DWORD SEND_THIS = 0x0073D958;
            static constexpr DWORD FUNC_WALK = 0x005F0C40;
            static constexpr DWORD FUNC_FOLLOW = 0x005F4A70;
            static constexpr DWORD FUNC_SEND = 0x00563E00;
            static constexpr DWORD FUNC_LOGIN = 0x004BAA80;
            static constexpr DWORD FUNC_POST_LOGIN_1 = 0x004B9F30;
            static constexpr DWORD FUNC_POST_LOGIN_2 = 0x004159C0;
            static constexpr DWORD DATA_POST_LOGIN_STATIC = 0x0073D95C;
        };
    }
}

