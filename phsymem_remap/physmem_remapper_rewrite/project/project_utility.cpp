#include "project_includes.hpp"
#include "windows_structs.hpp"
#include <ntimage.h>

extern "C" PLIST_ENTRY PsLoadedModuleList;

namespace utility {

    project_status get_driver_module_base(const wchar_t* driver_name, void*& driver_base) {
        PLIST_ENTRY head = PsLoadedModuleList;
        PLIST_ENTRY curr = head->Flink;

        // Just loop over the modules
        while (curr != head) {
            LDR_DATA_TABLE_ENTRY* curr_mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (crt::_wcsicmp(curr_mod->BaseDllName.Buffer, driver_name) == 0) {
                driver_base = curr_mod->DllBase;
                return status_success;
            }

            curr = curr->Flink;
        }

        return status_failure;
    }

    project_status get_eprocess(const char* process_name, PEPROCESS& pe_proc) {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;

        char image_name[15];

        do {
            crt::memcpy((void*)(&image_name), (void*)((uintptr_t)curr_entry + 0x5a8), sizeof(image_name));

            if (crt::strcmp(image_name, process_name) == 0) {
                uint32_t active_threads;

                crt::memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

                if (active_threads) {
                    pe_proc = curr_entry;
                    return status_success;
                }
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

        } while (curr_entry != sys_process);

        return status_failure;
    }

    uintptr_t find_pattern_in_range(uintptr_t region_base, size_t region_size, const char* pattern, size_t pattern_size, char wildcard) {
        // Ensure there are enough bytes left to check the pattern
        char* region_end = (char*)region_base + region_size - pattern_size + 1;

        for (char* byte = (char*)region_base; byte < region_end; ++byte) {

            if (*byte == *pattern || *pattern == wildcard) {
                bool found = true;

                for (size_t i = 1; i < pattern_size; ++i) {
                    if (pattern[i] != byte[i] && pattern[i] != wildcard) {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    return (uintptr_t)byte;
                }
            }
        }

        return 0;
    }

    uintptr_t search_pattern_in_section(void* module_handle, const char* section_name, const char* pattern, uint64_t pattern_size, char wildcard) {

        IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_handle;
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }

        IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)((uintptr_t)module_handle + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        // First section header is directly after NT Headers
        IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uintptr_t)nt_headers + sizeof(IMAGE_NT_HEADERS64));

        for (uint32_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            // Limit yourself to only executable non-discardable sections
            if (!(sections[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                (sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
                continue;
            if (crt::strncmp((const char*)sections[i].Name, section_name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
                uintptr_t section_start = (uintptr_t)module_handle + sections[i].VirtualAddress;
                uint32_t section_size = sections[i].Misc.VirtualSize;

                uintptr_t result = find_pattern_in_range((uintptr_t)section_start, section_size, pattern, pattern_size, wildcard);

                return result;
            }
        }

        return 0;
    }

    project_status is_data_ptr_valid(uint64_t data_ptr) {
        PLIST_ENTRY head = PsLoadedModuleList;
        PLIST_ENTRY curr = head->Flink;

        // Just loop over the modules
        while (curr != head) {
            LDR_DATA_TABLE_ENTRY* curr_mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            uint64_t driver_base = (uint64_t)curr_mod->DllBase;
            uint64_t driver_end = (uint64_t)curr_mod->DllBase + curr_mod->SizeOfImage;

            // If the data ptr resides in a legit driver, it is considered valid
            if (data_ptr >= driver_base && driver_end >= data_ptr)
                return status_success;

            curr = curr->Flink;
        }

        return status_data_ptr_invalid;
    }

    uint64_t get_cr3(uint64_t target_pid) {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;

        do {
            uint64_t curr_pid;

            crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(curr_pid));

            // Check whether we found our process
            if (target_pid == curr_pid) {

                uint32_t active_threads;

                crt::memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

                if (active_threads || target_pid == 4) {
                    uint64_t cr3;

                    crt::memcpy(&cr3, (void*)((uintptr_t)curr_entry + 0x28), sizeof(cr3));

                    return cr3;
                }
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry) + 0x448);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);
        } while (curr_entry != sys_process);

        return 0;
    }
};