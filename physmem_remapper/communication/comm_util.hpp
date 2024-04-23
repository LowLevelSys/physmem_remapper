#pragma once
#include "comm.hpp"
#include "../idt/safe_crt.hpp"

#define MAX_PATH 260

inline uint64_t get_pid(const char* target_process_name) {
    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;

    char image_name[15];

    // Easy way for system pid
    if (safe_crt::strstr(target_process_name, "System"))
        return 4;

    do {
        safe_crt::memcpy(&image_name, (void*)((uintptr_t)curr_entry + 0x5a8), sizeof(image_name));

        // Check whether we found our process
        if (safe_crt::strstr(image_name, target_process_name) || safe_crt::strstr(target_process_name, image_name)) {

            uint64_t pid = 0;

            safe_crt::memcpy(&pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(pid));

            return pid;
        }
        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry) + 0x448);
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

    } while (curr_entry != sys_process);

    return 0;
}

inline uint64_t get_cr3(uint64_t target_pid) {
    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;

    do {
        uint64_t curr_pid;

        safe_crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(curr_pid));

        // Check whether we found our process
        if (target_pid == curr_pid) {

            uint64_t cr3;

            safe_crt::memcpy(&cr3, (void*)((uintptr_t)curr_entry + 0x28), sizeof(cr3));

            return cr3;
        }
        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry) + 0x448);
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

    } while (curr_entry != sys_process);

    return 0;
}

// Gets the ldr data table entry of a sepecifc module in a specific process
inline LDR_DATA_TABLE_ENTRY get_ldr_data_table_entry(uint64_t target_pid, char* module_name) {
    physmem* inst = physmem::get_physmem_instance();

    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;

    paging_structs::cr3 user_cr3 = { 0 };

    do {
        uint64_t curr_pid;

        safe_crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(curr_pid));

        // Check whether we found our process
        if (target_pid == curr_pid) {

            uint64_t dtb;
            uint64_t peb;

            safe_crt::memcpy(&dtb, (void*)((uintptr_t)curr_entry + 0x28), sizeof(dtb));

            safe_crt::memcpy(&peb, (void*)((uintptr_t)curr_entry + 0x550), sizeof(peb));

            user_cr3.address_of_page_directory = dtb >> 12;

            // From now on we have to copy everything from the dtb using the user cr3
            uint64_t p_ldr;

            if (sizeof(p_ldr) != inst->copy_memory_to_inside(user_cr3, peb + 0x18, (uint64_t)&p_ldr, sizeof(p_ldr))) {
                dbg_log_handler("Failed to copy Ldr data ptr");
                return { 0 };
            }

            PEB_LDR_DATA ldr_data;

            if (sizeof(ldr_data) != inst->copy_memory_to_inside(user_cr3, p_ldr, (uint64_t)&ldr_data, sizeof(ldr_data))) {
                dbg_log_handler("Failed to copy Ldr data");
                return { 0 };
            }

            LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
            LIST_ENTRY* next_link = remote_flink;

            do {
                LDR_DATA_TABLE_ENTRY entry;

                if (sizeof(LDR_DATA_TABLE_ENTRY) != inst->copy_memory_to_inside(user_cr3, (uint64_t)next_link, (uint64_t)&entry, sizeof(LDR_DATA_TABLE_ENTRY))) {
                    dbg_log_handler("Failed to copy Ldr data table entry");
                    return { 0 };
                }

                wchar_t dll_name_buffer[MAX_PATH] = { 0 };
                char char_dll_name_buffer[MAX_PATH] = { 0 };

                if (entry.BaseDllName.Length != inst->copy_memory_to_inside(user_cr3, (uint64_t)entry.BaseDllName.Buffer, (uint64_t)&dll_name_buffer, entry.BaseDllName.Length)) {
                    dbg_log_handler("Failed to module name");
                    return { 0 };
                }

                for (uint64_t i = 0; i < entry.BaseDllName.Length / sizeof(wchar_t) && i < MAX_PATH - 1; i++)
                    char_dll_name_buffer[i] = (char)dll_name_buffer[i];

                char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

                if (safe_crt::strstr(char_dll_name_buffer, module_name))
                    return entry;

                next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
            } while (next_link && next_link != remote_flink);


            return { 0 };
        }

        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry) + 0x448); // apl offset
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448); // apl offset

    } while (curr_entry != sys_process);

    return { 0 };
}

inline uint64_t get_data_table_entry_count(uint64_t target_pid) {
    physmem* inst = physmem::get_physmem_instance();

    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;

    paging_structs::cr3 user_cr3 = { 0 };

    do {
        uint64_t curr_pid;

        safe_crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(curr_pid));

        // Check whether we found our process
        if (target_pid == curr_pid) {

            uint64_t dtb;
            uint64_t peb;

            safe_crt::memcpy(&dtb, (void*)((uintptr_t)curr_entry + 0x28), sizeof(dtb));

            safe_crt::memcpy(&peb, (void*)((uintptr_t)curr_entry + 0x550), sizeof(peb));

            user_cr3.address_of_page_directory = dtb >> 12;

            // From now on we have to copy everything from the dtb using the user cr3
            uint64_t p_ldr;

            if (sizeof(p_ldr) != inst->copy_memory_to_inside(user_cr3, peb + 0x18, (uint64_t)&p_ldr, sizeof(p_ldr))) {
                dbg_log_handler("Failed to copy Ldr data ptr");
                return 0;
            }

            PEB_LDR_DATA ldr_data;

            if (sizeof(ldr_data) != inst->copy_memory_to_inside(user_cr3, p_ldr, (uint64_t)&ldr_data, sizeof(ldr_data))) {
                dbg_log_handler("Failed to copy Ldr data");
                return 0;
            }

            LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
            LIST_ENTRY* next_link = remote_flink;
            uint64_t module_count = 0;

            do {
                LDR_DATA_TABLE_ENTRY entry;

                if (sizeof(LDR_DATA_TABLE_ENTRY) != inst->copy_memory_to_inside(user_cr3, (uint64_t)next_link, (uint64_t)&entry, sizeof(LDR_DATA_TABLE_ENTRY))) {
                    dbg_log_handler("Failed to copy Ldr data table entry");
                    return module_count;
                }

                wchar_t dll_name_buffer[MAX_PATH] = { 0 };
                char char_dll_name_buffer[MAX_PATH] = { 0 };

                if (entry.BaseDllName.Length != inst->copy_memory_to_inside(user_cr3, (uint64_t)entry.BaseDllName.Buffer, (uint64_t)&dll_name_buffer, entry.BaseDllName.Length)) {
                    dbg_log_handler("Failed to module name");
                    return { 0 };
                }

                for (uint64_t i = 0; i < entry.BaseDllName.Length / sizeof(wchar_t) && i < MAX_PATH - 1; i++)
                    char_dll_name_buffer[i] = (char)dll_name_buffer[i];

                char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

                dbg_log_handler("Dll %s", char_dll_name_buffer);

                module_count++;
                next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
            } while (next_link && next_link != remote_flink);

            return module_count;
        }
        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry) + 0x448); // apl offset
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448); // apl offset

    } while (curr_entry != sys_process);

    return 0;
}

inline bool get_data_table_entry_info(uint64_t target_pid, module_info_t* info_array, paging_structs::cr3 proc_cr3) {
    physmem* inst = physmem::get_physmem_instance();
    module_info_t* curr_info_entry = info_array;

    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;

    paging_structs::cr3 user_cr3 = { 0 };

    if (!curr_info_entry) {
        dbg_log_handler("Invalid parameter");
        return false;
    }

    do {
        uint64_t curr_pid;

        safe_crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(curr_pid));

        // Check whether we found our process
        if (target_pid == curr_pid) {

            uint64_t dtb;
            uint64_t peb;

            safe_crt::memcpy(&dtb, (void*)((uintptr_t)curr_entry + 0x28), sizeof(dtb));

            safe_crt::memcpy(&peb, (void*)((uintptr_t)curr_entry + 0x550), sizeof(peb));

            user_cr3.address_of_page_directory = dtb >> 12;

            // From now on we have to copy everything from the dtb using the user cr3
            uint64_t p_ldr;

            if (sizeof(p_ldr) != inst->copy_memory_to_inside(user_cr3, peb + 0x18, (uint64_t)&p_ldr, sizeof(p_ldr))) {
                dbg_log_handler("Failed to copy Ldr data ptr");
                return false;
            }

            PEB_LDR_DATA ldr_data;

            if (sizeof(ldr_data) != inst->copy_memory_to_inside(user_cr3, p_ldr, (uint64_t)&ldr_data, sizeof(ldr_data))) {
                dbg_log_handler("Failed to copy Ldr data");
                return false;
            }

            LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
            LIST_ENTRY* next_link = remote_flink;

            do {
                LDR_DATA_TABLE_ENTRY entry;

                if (sizeof(LDR_DATA_TABLE_ENTRY) != inst->copy_memory_to_inside(user_cr3, (uint64_t)next_link, (uint64_t)&entry, sizeof(LDR_DATA_TABLE_ENTRY))) {
                    dbg_log_handler("Failed to copy Ldr data table entry");
                    return false;
                }

                wchar_t dll_name_buffer[MAX_PATH] = { 0 };
                char char_dll_name_buffer[MAX_PATH] = { 0 };

                if (entry.BaseDllName.Length != inst->copy_memory_to_inside(user_cr3, (uint64_t)entry.BaseDllName.Buffer, (uint64_t)&dll_name_buffer, entry.BaseDllName.Length)) {
                    dbg_log_handler("Failed to copy module name");
                    return false;
                }

                for (uint64_t i = 0; i < entry.BaseDllName.Length / sizeof(wchar_t) && i < MAX_PATH - 1; i++)
                    char_dll_name_buffer[i] = (char)dll_name_buffer[i];

                char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

                module_info_t info = { 0 };
                info.base = (uint64_t)entry.DllBase;
                info.size = entry.SizeOfImage;
                safe_crt::memcpy(&info.name, &char_dll_name_buffer, min(entry.BaseDllName.Length / sizeof(wchar_t), MAX_PATH - 1));

                if (sizeof(module_info_t) != inst->copy_memory_from_inside((uint64_t)&info, (uint64_t)curr_info_entry, proc_cr3, sizeof(module_info_t))) {
                    dbg_log_handler("Failed to copy module info to um");
                    return false;
                }

                curr_info_entry++;

                next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
            } while (next_link && next_link != remote_flink);

            return true;
        }
        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448); // apl offset
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448); // apl offset

    } while (curr_entry != sys_process);

    return false;
}

inline uint64_t get_module_base(uint64_t target_pid, char* module_name) {
    LDR_DATA_TABLE_ENTRY entry = get_ldr_data_table_entry(target_pid, module_name);

    return (uint64_t)entry.DllBase;
}

inline uint64_t get_module_size(uint64_t target_pid, char* module_name) {
    LDR_DATA_TABLE_ENTRY entry = get_ldr_data_table_entry(target_pid, module_name);

    return (uint64_t)entry.SizeOfImage;
}