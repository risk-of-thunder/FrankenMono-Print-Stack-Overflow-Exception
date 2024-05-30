#include <Windows.h>

#include "Global.h"
#include "Detours/include/detours.h"

#include <libloaderapi.h>
#include <processthreadsapi.h>
#include <Psapi.h>

struct module_info_helper
{
    static inline void get_module_base_and_size(uintptr_t* base, size_t* size, const char* module_name = nullptr)
    {
        *base = {};
        *size = {};

        MODULEINFO module_info = {};

        HMODULE module = GetModuleHandleA(module_name);
        if (module)
        {
            GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof MODULEINFO);
        }

        if (base)
        {
            *base = uintptr_t(module_info.lpBaseOfDll);
        }
        if (size)
        {
            *size = size_t(module_info.SizeOfImage);
        }
    }
};

/**
 * \brief Provides compact utility to scan patterns and manipulate addresses.
 */
struct gmAddress
{
    uint64_t m_value = 0;

    gmAddress(uint64_t value) :
        m_value(value)
    {
    }

    gmAddress() :
        gmAddress(0)
    {
    }

private:
    static inline uint64_t s_module_base_default_module;
    static inline uint64_t s_module_size_default_module;

    static void init_if_needed_default_module_info()
    {
        static bool is_init = false;
        if (!is_init)
        {
            module_info_helper::get_module_base_and_size(&s_module_base_default_module, &s_module_size_default_module, "mono-2.0-bdwgc.dll");
            is_init = true;
        }
    }

    static gmAddress scan_internal(const char* pattern_str, const char* debug_name, uint64_t module_base, uint64_t module_size)
    {
        // Convert string pattern into byte array form
        int16_t pattern[256];
        uint8_t pattern_size = 0;
        for (size_t i = 0; i < strlen(pattern_str); i += 3)
        {
            const char* cursor = pattern_str + i;

            if (cursor[0] == '?')
            {
                pattern[pattern_size] = -1;
            }
            else
            {
                pattern[pattern_size] = static_cast<int16_t>(strtol(cursor, nullptr, 16));
            }

            // Support single '?' (we're incrementing by 3 expecting ?? and space, but with ? we must increment by 2)
            if (cursor[1] == ' ')
            {
                i--;
            }

            pattern_size++;
        }

        // In two-end comparison we approach from both sides (left & right) so size is twice smaller
        uint8_t scan_size = pattern_size;
        if (scan_size % 2 == 0)
        {
            scan_size /= 2;
        }
        else
        {
            scan_size = pattern_size / 2 + 1;
        }

        // Search for string through whole module
        // We use two-end comparison, nothing fancy but better than just brute force
        for (uint64_t i = 0; i < module_size; i += 1)
        {
            const uint8_t* module_position = (uint8_t*)(module_base + i);
            for (uint8_t j = 0; j < scan_size; j++)
            {
                int16_t left_expected = pattern[j];
                int16_t left_actual = module_position[j];

                if (left_expected != -1 && left_actual != left_expected)
                {
                    goto miss;
                }

                int16_t right_expected = pattern[pattern_size - j - 1];
                int16_t right_actual = module_position[pattern_size - j - 1];

                if (right_expected != -1 && right_actual != right_expected)
                {
                    goto miss;
                }
            }
            return { module_base + i };
        miss:;
        }

        if (debug_name)
        {
            //LOG(ERROR) << "Missed " << debug_name;
        }
        return { 0 };
    }

public:
    static gmAddress scan(const char* pattern_str, const char* debug_name = nullptr)
    {
        init_if_needed_default_module_info();

        return scan_internal(pattern_str, debug_name, s_module_base_default_module, s_module_size_default_module);
    }

    gmAddress offset(int32_t offset) const
    {
        return m_value + offset;
    }

    gmAddress rip(int32_t offset = 0) const
    {
        return m_value + offset + 4 + *(int32_t*)(m_value + offset);
    }

    gmAddress get_call() const
    {
        return rip(1);
    }

    template<typename T>
    T as() const
    {
        return (T)m_value;
    }

    template<typename T>
    T* as_func() const
    {
        return as<T*>();
    }

    gmAddress& operator=(uint64_t value)
    {
        m_value = value;
        return *this;
    }

    operator uint64_t() const
    {
        return m_value;
    }

    operator void* () const
    {
        return (void*)m_value;
    }
};

/*
 * detours.h do not contain these structs so we need to redifine it here.
 * You can find the original definition in detours.cpp in the library source code.
 */
struct DETOUR_ALIGN
{
    BYTE    obTarget : 3;
    BYTE    obTrampoline : 5;
};

struct DETOUR_INFO
{
    // An X64 instuction can be 15 bytes long.
    // In practice 11 seems to be the limit.
    BYTE            rbCode[30];     // target code + jmp to pbRemain.
    BYTE            cbCode;         // size of moved target code.
    BYTE            cbCodeBreak;    // padding to make debugging easier.
    BYTE            rbRestore[30];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            cbRestoreBreak; // padding to make debugging easier.
    DETOUR_ALIGN    rAlign[8];      // instruction alignment array.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
    BYTE            rbCodeIn[8];    // jmp [pbDetour]
};

using lpGetValueFnc = INT64(*)();

void InitHook()
{
    PDETOUR_TRAMPOLINE lpTrampolineData = {};

    // mono-2.0-bdwgc.dll - int __cdecl resetstkoflw()
    // .text:   00000001803632DD 33 DB              xor     ebx, ebx
    // .text:   00000001803632DF 21 5D 00           and     [rbp + 80h + var_80], ebx
    // inject here and fix rsp
    // .text:   00000001803632E2 E8 25 80 00 00     call    __acrt_SetThreadStackGuarantee
    // .text :  00000001803632E7 85 C0              test    eax, eax

    static auto lpGetValue_ptr = gmAddress::scan("33 DB 21 5D 00");
    if (lpGetValue_ptr)
    {
        static auto lpGetValue = lpGetValue_ptr.offset(2).as<PVOID>();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        // Use DetourAttachEx to retrieve information about the hook
        DetourAttachEx((PVOID*)&lpGetValue, (PVOID)&hkGetValue, &lpTrampolineData, nullptr, nullptr);
        DetourTransactionCommit();

        const auto lpDetourInfo = (DETOUR_INFO*)lpTrampolineData;
        // Retrieve the address to jump back the original function
        lpRemain = lpDetourInfo->pbRemain;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        InitHook();
    }

    return TRUE;
}