#pragma once
#include "comm.hpp"

#define MAX_PATH 260

inline uint64_t get_pid(const char* target_process_name) {
    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;

    char image_name[15];

    // Easy way for system pid
    if (crt::strstr(target_process_name, "System"))
        return 4;

    do {
        crt::memcpy(&image_name, (void*)((uintptr_t)curr_entry + 0x5a8), sizeof(image_name));

        // Check whether we found our process
        if (crt::strstr(image_name, target_process_name) || crt::strstr(target_process_name, image_name)) {

            uint64_t pid = 0;
            
            crt::memcpy(&pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(pid));

            return pid;
        }
        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

    } while (curr_entry != sys_process);

    return 0;
}

inline uint64_t get_cr3(uint64_t target_pid) {
    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;

    do {
        uint64_t curr_pid;

        crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(curr_pid));

        // Check whether we found our process
        if (target_pid == curr_pid) {

            uint64_t cr3;

            crt::memcpy(&cr3, (void*)((uintptr_t)curr_entry + 0x28), sizeof(cr3));

            return cr3;
        }
        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

    } while (curr_entry != sys_process);

    return 0;
}

// Gets the ldr data table entry of a sepecifc module in a specific process
inline LDR_DATA_TABLE_ENTRY get_ldr_data_table_entry(uint64_t target_pid, char* module_name) {
    physmem* inst = physmem::get_physmem_instance();

    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS curr_entry = sys_process;

    paging_structs::cr3 curr_cr3;
    paging_structs::cr3 user_cr3;
    user_cr3.flags = inst->get_kernel_cr3().flags;
    curr_cr3.flags = __readcr3();

    do {
        uint64_t curr_pid;

        crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(curr_pid));

        // Check whether we found our process
        if (target_pid == curr_pid) {

            uint64_t dtb;
            uint64_t peb;

            crt::memcpy(&dtb, (void*)((uintptr_t)curr_entry + 0x28), sizeof(dtb));

            crt::memcpy(&peb, (void*)((uintptr_t)curr_entry + 0x550), sizeof(peb));

            user_cr3.address_of_page_directory = dtb >> 12;

            // From now on we have to copy everything from the dtb using the user cr3
            uint64_t p_ldr;
            PEB_LDR_DATA ldr_data;

            if (sizeof(p_ldr) != inst->copy_virtual_memory(user_cr3, peb + 0x18, curr_cr3, (uint64_t)&p_ldr, sizeof(p_ldr))) {
                dbg_log("Failed to copy Ldr data ptr");
                return { 0 };
            }

            if (sizeof(ldr_data) != inst->copy_virtual_memory(user_cr3, p_ldr, curr_cr3, (uint64_t)&ldr_data, sizeof(ldr_data))) {
                dbg_log("Failed to copy Ldr data");
                return { 0 };
            }

            uint64_t ldr_head = (uint64_t)ldr_data.InLoadOrderModuleList.Flink;
            uint64_t ldr_curr = ldr_head;

            do
            {
                LDR_DATA_TABLE_ENTRY curr_ldr_entry = { 0 };

                if (sizeof(curr_ldr_entry) != inst->copy_virtual_memory(user_cr3, ldr_curr, curr_cr3, (uint64_t)&curr_ldr_entry, sizeof(curr_ldr_entry))) {
                    dbg_log("Failed to copy Ldr data table entry");
                    return { 0 };
                }

                wchar_t dll_name_buffer[MAX_PATH] = { 0 };
                char char_dll_name_buffer[MAX_PATH] = { 0 };


                if (curr_ldr_entry.BaseDllName.Length != inst->copy_virtual_memory(user_cr3, (uint64_t)curr_ldr_entry.BaseDllName.Buffer, curr_cr3, (uint64_t)&dll_name_buffer, curr_ldr_entry.BaseDllName.Length)) 
                    continue;
               
                for (uint64_t i = 0; i < curr_ldr_entry.BaseDllName.Length / sizeof(wchar_t) && i < MAX_PATH - 1; i++)
                    char_dll_name_buffer[i] = (char)dll_name_buffer[i];
                

                // Ignore lower / upper case in order to ensure you find it (and contains therefore if the msg is cut off it still works)
                if (crt::strstr(char_dll_name_buffer, module_name)) 
                    return curr_ldr_entry;
                

                ldr_curr = (uint64_t)curr_ldr_entry.InLoadOrderLinks.Flink;

            } while (ldr_curr != ldr_head);


        }
        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry) + 0x448);
        curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

    } while (curr_entry != sys_process);


    return { 0 };
}

inline uint64_t get_module_base(uint64_t target_pid, char* module_name) {
    LDR_DATA_TABLE_ENTRY entry = get_ldr_data_table_entry(target_pid, module_name);

    return (uint64_t)entry.DllBase;
}

inline uint64_t get_module_size(uint64_t target_pid, char* module_name) {
    LDR_DATA_TABLE_ENTRY entry = get_ldr_data_table_entry(target_pid, module_name);

    return (uint64_t)entry.SizeOfImage;
}