#pragma once
#include "driver_includes.hpp"
#include "driver_shared.hpp"

typedef __int64(__fastcall* NtUserGetCPD_type)(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data);

constexpr uint32_t caller_signature = 0x6969;
constexpr uint32_t call_in_progress_signature = 0x9696;

class physmem_remapper_um_t {
private:

    static physmem_remapper_um_t* instance;
    std::mutex mtx;

    bool inited = false;
    NtUserGetCPD_type NtUserGetCPD = (NtUserGetCPD_type)0;
    __int64 send_request(void* cmd, void* nmi_panic_function) const;

public:
    bool copy_virtual_memory(uint64_t source_cr3, uint64_t destination_cr3, void* source, void* destination, uint64_t size);
    uint64_t get_cr3(uint64_t pid);
    uint64_t get_module_base(const char* module_name, uint64_t pid);
    uint64_t get_module_size(const char* module_name, uint64_t pid);
    uint64_t get_pid_by_name(const char* name);
    uint64_t get_ldr_data_table_entry_count(uint64_t pid);
    bool get_data_table_entry_info(uint64_t pid, module_info_t* info_array);
    bool remove_apc();
    bool restore_apc();


    static physmem_remapper_um_t* init_physmem_remapper_lib(void) {

        if (instance) {
            log("Already inited");
            return instance;
        }

        auto temp = new physmem_remapper_um_t;
        memset(temp, 0, sizeof(physmem_remapper_um_t));

        instance = temp;

        if (!instance) {
            log("Why tf is the new keyword not functioning");
            return 0;
        }


        // For some reason user32.dll has to also be loaded for calls to NtUser functions to work?
        if (!LoadLibraryW(L"user32.dll")) {
            log("Failed to load user32.dll");
            return 0;
        }

        HMODULE win32u = LoadLibraryW(L"win32u.dll");
        if (!win32u) {
            log("Failed to get win32u.dll handle");
            return 0;
        }

        uint64_t handler_address = (uint64_t)GetProcAddress(win32u, "NtUserGetCPD");

        instance->NtUserGetCPD = (NtUserGetCPD_type)handler_address;

        instance->inited = true;

        return instance;
    }

    bool is_lib_inited(void) {
        return instance->inited;
    }
};