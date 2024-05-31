#include "communication.hpp"
#include "shared_structs.hpp"

#include "../project_api.hpp"
#include "../project_utility.hpp"

namespace handler_utility {
    uint64_t get_pid(const char* target_process_name) {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;

        char image_name[IMAGE_NAME_LENGTH];

        // Easy way for system pid
        if (strstr(target_process_name, "System"))
            return SYSTEM_PID;

        do {
            uint32_t active_threads;

            memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

            if (!active_threads) {
                PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+ FLINK_OFFSET);
                curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
                continue;
            }

            memcpy(&image_name, (void*)((uintptr_t)curr_entry + IMAGE_NAME_OFFSET), IMAGE_NAME_LENGTH);

            // Check whether we found our process
            if (strstr(image_name, target_process_name) || strstr(target_process_name, image_name)) {
                uint64_t pid = 0;

                memcpy(&pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(pid));

                return pid;
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
        } while (curr_entry != sys_process);

        return 0;
    }

    project_status get_ldr_data_table_entry(uint64_t target_pid, char* module_name, LDR_DATA_TABLE_ENTRY* module_entry) {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;
        project_status status = status_success;
        if (!module_entry || !target_pid || !module_name)
            return status_invalid_parameter;

        do {
            uint32_t active_threads;

            memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

            if (!active_threads) {
                PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
                curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
                continue;
            }

            uint64_t curr_pid;

            memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(curr_pid));

            if (target_pid == curr_pid) {
                uint64_t dtb;
                uint64_t peb;

                memcpy(&dtb, (void*)((uintptr_t)curr_entry + DIRECTORY_TABLE_BASE_OFFSET), sizeof(dtb));
                memcpy(&peb, (void*)((uintptr_t)curr_entry + PEB_OFFSET), sizeof(peb));

                PEB_LDR_DATA* pldr;
                status = physmem::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dtb);
                if (status != status_success)
                    break;

                PEB_LDR_DATA ldr_data;
                status = physmem::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dtb);
                if (status != status_success)
                    break;

                LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
                LIST_ENTRY* next_link = remote_flink;
    
                do {
                    LDR_DATA_TABLE_ENTRY entry;
                    status = physmem::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dtb);
                    if (status != status_success)
                        break;

                    wchar_t dll_name_buffer[MAX_PATH] = { 0 };
                    char char_dll_name_buffer[MAX_PATH] = { 0 };

                    status = physmem::copy_memory_to_constructed_cr3(&dll_name_buffer, entry.BaseDllName.Buffer, entry.BaseDllName.Length, dtb);
                    if (status != status_success)
                        break;

                    for (uint64_t i = 0; i < entry.BaseDllName.Length / sizeof(wchar_t) && i < MAX_PATH - 1; i++)
                        char_dll_name_buffer[i] = (char)dll_name_buffer[i];

                    char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

                    if (strstr(char_dll_name_buffer, module_name)) {
                        memcpy(module_entry, &entry, sizeof(LDR_DATA_TABLE_ENTRY));
                        return status;
                    }

                    next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
                } while (next_link && next_link != remote_flink);

                status = status_failure;
                return status;
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry) + FLINK_OFFSET);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);

        } while (curr_entry != sys_process);

        status = status_failure;
        return status;
    }

    uint64_t get_data_table_entry_count(uint64_t target_pid) {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;
        project_status status = status_success;
        if (!target_pid)
            return status_invalid_parameter;

        do {
            uint32_t active_threads;

            memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

            if (!active_threads) {
                PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
                curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
                continue;
            }

            uint64_t curr_pid;

            memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(curr_pid));

            if (target_pid == curr_pid) {
                uint64_t dtb;
                uint64_t peb;

                memcpy(&dtb, (void*)((uintptr_t)curr_entry + DIRECTORY_TABLE_BASE_OFFSET), sizeof(dtb));
                memcpy(&peb, (void*)((uintptr_t)curr_entry + PEB_OFFSET), sizeof(peb));

                PEB_LDR_DATA* pldr;
                status = physmem::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dtb);
                if (status != status_success)
                    break;

                PEB_LDR_DATA ldr_data;
                status = physmem::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dtb);
                if (status != status_success)
                    break;

                LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
                LIST_ENTRY* next_link = remote_flink;
                uint64_t module_count = 0;

                do {
                    LDR_DATA_TABLE_ENTRY entry;
                    status = physmem::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dtb);
                    if (status != status_success)
                        return module_count;

                    module_count++;
                    next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
                } while (next_link && next_link != remote_flink);

                return module_count;
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry) + FLINK_OFFSET);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);

        } while (curr_entry != sys_process);

        return 0;
    }

    project_status get_data_table_entry_info(uint64_t target_pid, module_info_t* info_array, uint64_t proc_cr3) {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;
        project_status status = status_success;
        uint64_t curr_info_entry = (uint64_t)info_array;

        if (!target_pid || !info_array || !proc_cr3)
            return status_invalid_parameter;

        do {
            uint32_t active_threads;

            memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

            if (!active_threads) {
                PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
                curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
                continue;
            }

            uint64_t curr_pid;

            memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(curr_pid));

            if (target_pid == curr_pid) {
                uint64_t dtb;
                uint64_t peb;

                memcpy(&dtb, (void*)((uintptr_t)curr_entry + DIRECTORY_TABLE_BASE_OFFSET), sizeof(dtb));
                memcpy(&peb, (void*)((uintptr_t)curr_entry + PEB_OFFSET), sizeof(peb));

                PEB_LDR_DATA* pldr;
                status = physmem::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dtb);
                if (status != status_success)
                    break;

                PEB_LDR_DATA ldr_data;
                status = physmem::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dtb);
                if (status != status_success)
                    break;

                LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
                LIST_ENTRY* next_link = remote_flink;

                do {
                    LDR_DATA_TABLE_ENTRY entry;
                    status = physmem::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dtb);
                    if (status != status_success)
                        break;

                    wchar_t dll_name_buffer[MAX_PATH] = { 0 };
                    char char_dll_name_buffer[MAX_PATH] = { 0 };

                    status = physmem::copy_memory_to_constructed_cr3(&dll_name_buffer, entry.BaseDllName.Buffer, entry.BaseDllName.Length, dtb);
                    if (status != status_success) {
                        next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
                        continue;
                    }

                    for (uint64_t i = 0; i < entry.BaseDllName.Length / sizeof(wchar_t) && i < MAX_PATH - 1; i++)
                        char_dll_name_buffer[i] = (char)dll_name_buffer[i];

                    char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

                    module_info_t info = { 0 };
                    info.base = (uint64_t)entry.DllBase;
                    info.size = entry.SizeOfImage;
                    memcpy(&info.name, &char_dll_name_buffer, min(entry.BaseDllName.Length / sizeof(wchar_t), MAX_PATH - 1));

                    status = physmem::copy_memory_from_constructed_cr3((void*)curr_info_entry, &info, sizeof(module_info_t), proc_cr3);
                    if (status != status_success) {
                        next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
                        continue;
                    }

                    curr_info_entry += sizeof(module_info_t);
                    next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
                } while (next_link && next_link != remote_flink);

                return status;
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry) + FLINK_OFFSET);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);

        } while (curr_entry != sys_process);

        status = status_failure;
        return status;
    }

    uint64_t get_module_base(uint64_t target_pid, char* module_name) {
        LDR_DATA_TABLE_ENTRY data_table_entry;

        project_status status = get_ldr_data_table_entry(target_pid, module_name, &data_table_entry);
        if (status != status_success)
            return 0;

        return (uint64_t)data_table_entry.DllBase;
    }

    uint64_t get_module_size(uint64_t target_pid, char* module_name) {
        LDR_DATA_TABLE_ENTRY data_table_entry;

        project_status status = get_ldr_data_table_entry(target_pid, module_name, &data_table_entry);
        if (status != status_success)
            return 0;

        return (uint64_t)data_table_entry.SizeOfImage;
    }
};