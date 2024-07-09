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
        if (crt::strstr(target_process_name, "System"))
            return SYSTEM_PID;

        do {
            uint32_t active_threads;

            crt::memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

            if (!active_threads) {
                PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
                curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
                continue;
            }

            crt::memcpy(&image_name, (void*)((uintptr_t)curr_entry + IMAGE_NAME_OFFSET), IMAGE_NAME_LENGTH);

            // Check whether we found our process
            if (crt::strstr(image_name, target_process_name) || crt::strstr(target_process_name, image_name)) {
                uint64_t pid = 0;

                crt::memcpy(&pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(pid));

                return pid;
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
        } while (curr_entry != sys_process);

        return 0;
    }

    void* get_eprocess(uint64_t target_pid) {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;

        // Easy way for system pid
        if (target_pid == SYSTEM_PID)
            return sys_process;

        do {
            uint32_t active_threads;

            crt::memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

            if (!active_threads) {
                PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
                curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
                continue;
            }

            uint64_t curr_pid;
            crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(curr_pid));

            // Check whether we found our process
            if (curr_pid == target_pid) {
                return curr_entry;
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

            crt::memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

            if (!active_threads) {
                PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
                curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
                continue;
            }

            uint64_t curr_pid;

            crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(curr_pid));

            if (target_pid == curr_pid) {
                uint64_t dtb;
                uint64_t peb;

                crt::memcpy(&dtb, (void*)((uintptr_t)curr_entry + DIRECTORY_TABLE_BASE_OFFSET), sizeof(dtb));
                crt::memcpy(&peb, (void*)((uintptr_t)curr_entry + PEB_OFFSET), sizeof(peb));

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

                    if (crt::strstr(char_dll_name_buffer, module_name)) {
                        crt::memcpy(module_entry, &entry, sizeof(LDR_DATA_TABLE_ENTRY));
                        return status;
                    }

                    next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
                } while (next_link && next_link != remote_flink);

                status = status_failure;
                return status;
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
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

            crt::memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

            if (!active_threads) {
                PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
                curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
                continue;
            }

            uint64_t curr_pid;

            crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(curr_pid));

            if (target_pid == curr_pid) {
                uint64_t dtb;
                uint64_t peb;

                crt::memcpy(&dtb, (void*)((uintptr_t)curr_entry + DIRECTORY_TABLE_BASE_OFFSET), sizeof(dtb));
                crt::memcpy(&peb, (void*)((uintptr_t)curr_entry + PEB_OFFSET), sizeof(peb));

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

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
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

            crt::memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

            if (!active_threads) {
                PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
                curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
                continue;
            }

            uint64_t curr_pid;

            crt::memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(curr_pid));

            if (target_pid == curr_pid) {
                uint64_t dtb;
                uint64_t peb;

                crt::memcpy(&dtb, (void*)((uintptr_t)curr_entry + DIRECTORY_TABLE_BASE_OFFSET), sizeof(dtb));
                crt::memcpy(&peb, (void*)((uintptr_t)curr_entry + PEB_OFFSET), sizeof(peb));

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
                    crt::memcpy(&info.name, &char_dll_name_buffer, min(entry.BaseDllName.Length / sizeof(wchar_t), MAX_PATH - 1));

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

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
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

    void* get_code_cave(void* base, uint32_t size, uint64_t target_cr3, uint64_t source_cr3) {
        // Ensure at least some alignment
        if (size < 8) {
            size = 8;
        }

        IMAGE_DOS_HEADER dos_header = { 0 };
        IMAGE_DOS_HEADER* pdos_header = (IMAGE_DOS_HEADER*)base;

        project_status status = physmem::copy_virtual_memory(&dos_header, pdos_header, sizeof(IMAGE_DOS_HEADER), target_cr3, source_cr3);
        if (status != status_success) {
            return nullptr;
        }

        IMAGE_NT_HEADERS nt_headers = { 0 };
        IMAGE_NT_HEADERS* pnt_headers = (IMAGE_NT_HEADERS*)((uint8_t*)base + dos_header.e_lfanew);

        status = physmem::copy_virtual_memory(&nt_headers, pnt_headers, sizeof(IMAGE_NT_HEADERS), target_cr3, source_cr3);
        if (status != status_success) {
            return nullptr;
        }

        IMAGE_SECTION_HEADER* section_headers = (IMAGE_SECTION_HEADER*)ExAllocatePoolWithTag(NonPagedPool, sizeof(IMAGE_SECTION_HEADER) * nt_headers.FileHeader.NumberOfSections, 'shdr');
        if (!section_headers) {
            return nullptr;
        }

        status = physmem::copy_virtual_memory(section_headers, (IMAGE_SECTION_HEADER*)(pnt_headers + 1),
            sizeof(IMAGE_SECTION_HEADER) * nt_headers.FileHeader.NumberOfSections,
            target_cr3, source_cr3);
        if (status != status_success) {
            ExFreePoolWithTag(section_headers, 'shdr'); // Clean up
            return nullptr;
        }

        uint8_t* local_buffer = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, 0x1000 + size - 1, 'lbuf'); // Buffer size is page size plus additional bytes to account for partial code caves at the end of pages
        if (!local_buffer) {
            ExFreePoolWithTag(section_headers, 'shdr');
            return nullptr;
        }

        void* cave_address = nullptr;

        for (unsigned short i = 0; i < nt_headers.FileHeader.NumberOfSections; ++i) {
            if (crt::memcmp(section_headers[i].Name, ".text", 5) == 0) {
                uint32_t section_size = section_headers[i].Misc.VirtualSize;
                uint8_t* section_base = (uint8_t*)base + section_headers[i].VirtualAddress;

                for (uint32_t offset = 0; offset < section_size; offset += 0x1000) {
                    uint32_t chunk_size = (offset + 0x1000 > section_size) ? section_size - offset : 0x1000;

                    status = physmem::copy_virtual_memory(local_buffer, section_base + offset, chunk_size, target_cr3, source_cr3);
                    if (status != status_success) {
                        ExFreePoolWithTag(section_headers, 'shdr'); // Clean up
                        ExFreePoolWithTag(local_buffer, 'lbuf');
                        return nullptr;
                    }

                    for (uint32_t j = 0; j < chunk_size; ++j) {
                        if (local_buffer[j] == 0xCC || local_buffer[j] == 0x00) {
                            uint8_t current_byte = local_buffer[j];
                            uint32_t k = 1;
                            for (; k < size && j + k < chunk_size; ++k) {
                                if (local_buffer[j + k] != current_byte) {
                                    break;
                                }
                            }

                            if (k == size) { // Code cave found
                                cave_address = section_base + offset + j;
                                goto cleanup;
                            }
                        }
                    }
                }
            }
        }

    cleanup:
        ExFreePoolWithTag(section_headers, 'shdr');
        ExFreePoolWithTag(local_buffer, 'lbuf');
        return cave_address;
    }

    project_status trigger_cow(void* target_address, uint64_t target_cr3, uint64_t source_cr3) {
        if (!target_address || !target_cr3 || !source_cr3)
            return status_invalid_parameter;

        project_status status;
        uint64_t physical_address;

        // Translate VA to PA
        status = physmem::translate_to_physical_address(source_cr3, target_address, physical_address);
        if (status != status_success)
            return status;

        if (!physical_address)
            return status_address_translation_failed;

        pte_64 dummy;
        pte_64* pte;

        // Get PTE for target address
        status = physmem::get_pte_entry(target_address, target_cr3, pte);
        if (status != status_success)
            return status;

        if (!pte)
            return status_failure;

        // Prepare PTE for COW
        dummy.flags = 0;
        dummy.present = true;
        dummy.write = true;
        dummy.supervisor = true;
        dummy.execute_disable = false;
        dummy.page_frame_number = physical_address >> 12;

        // Update PTE to point to the physical address
        *pte = dummy;

        __invlpg(target_address);

        physmem::safely_unmap_4kb_page(pte);

        return status_success;
    }

    project_status revert_cow_triggering(void* target_address, uint64_t target_cr3) {
        if (!target_address || !target_cr3)
            return status_invalid_parameter;

        project_status status;
        pte_64 dummy;
        pte_64* pte;
        status = physmem::get_pte_entry(target_address, target_cr3, pte);
        if (status != status_success)
            return status;

        if (!pte)
            return status_failure;

        dummy.flags = 0;
        *pte = dummy;

        __invlpg(target_address);

        physmem::safely_unmap_4kb_page(pte);

        return status_success;
    }

    project_status allocate_and_copy_kernel_buffer(void* target_address, uint64_t target_cr3, uint64_t source_cr3, void*& buffer, size_t size) {
        PHYSICAL_ADDRESS lowest_acceptable_address = { 0 };
        PHYSICAL_ADDRESS highest_acceptable_address;
        highest_acceptable_address.QuadPart = ~0ULL;
        PHYSICAL_ADDRESS boundary_address_multiple = { 0 };

        buffer = physmem::allocate_contiguous_memory_ex(size, lowest_acceptable_address, highest_acceptable_address,
            boundary_address_multiple, PAGE_EXECUTE_READWRITE, 'tmp7');

        if (!buffer)
            return status_memory_allocation_failed;

        project_status status = physmem::copy_virtual_memory(buffer, target_address, size, target_cr3, source_cr3);
        if (status != status_success)
            return status_failure;

        return status_success;
    };

    project_status update_pte_to_buffer(void* target_address, uint64_t target_cr3, void* buffer) {
        pte_64* pte;
        project_status status;
        uint64_t buffer_physical_address;

        status = physmem::translate_to_physical_address(target_cr3, buffer, buffer_physical_address);
        if (status != status_success)
            return status;

        status = physmem::get_pte_entry(target_address, target_cr3, pte);
        if (status != status_success)
            return status;

        if (!pte)
            return status_failure;

        pte->present = true;
        pte->write = true;
        pte->execute_disable = false;
        pte->page_frame_number = buffer_physical_address >> 12;

        __invlpg(target_address);

        physmem::safely_unmap_4kb_page(pte);

        return status_success;
    }
};