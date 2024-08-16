#include "communication.hpp"
#
#include "../project_api.hpp"
#include "../project_utility.hpp"

extern "C" info_page_t* g_info_page = 0;

namespace communication {
    /*
        Global variables
    */
    // Data ptr
    void** g_data_ptr_address = 0;
    void* g_orig_data_ptr_value = 0;

    // Gadgets
    void* g_used_gadget = 0; // This is where the data ptr will be pointed
    void* g_used_gadget_jump_destination = 0; // This is where the gadget will jump to (will contain mov rax jmp rax)

    // Shellcodes
    void* enter_constructed_space_executed = 0;
    void* enter_constructed_space_shown = 0;
    extern "C" void* exit_constructed_space = 0;
    extern "C" void* nmi_shellcode = 0;

    /*
        Util
    */
    void log_data_ptr_info(void) {
        project_log_info("Data ptr value stored at: %p", g_data_ptr_address);
        project_log_info("Orig data ptr value: %p", g_orig_data_ptr_value);
        project_log_info("Exchanged data ptr value: %p", asm_handler);
    }

    /*
        Initialization functions
    */
    namespace gadgets {
        struct gadget_info_t {
            void* gadget;
            void* jump_destination;
        };

        uint32_t simple_random() {
            static uint32_t seed = 0;
            if (!seed) {
                uint64_t tsc = __rdtsc();
                seed = (uint32_t)(tsc ^ (tsc >> 32));
            }
            seed = (1664525 * seed + 1013904223);
            return seed;
        }

        gadget_info_t* find_possible_gadgets(uint32_t& gadget_count) {
            PEPROCESS winlogon_eproc = 0;
            KAPC_STATE apc = { 0 };
            project_status status = status_success;
            void* win32k_base = 0;

            status = utility::get_eprocess("winlogon.exe", winlogon_eproc);
            if (status != status_success) {
                project_log_error("Failed to get winlogon.exe EPROCESS");
                return 0;
            }

            status = utility::get_driver_module_base(L"win32kfull.sys", win32k_base);
            if (status != status_success) {
                project_log_error("Failed to get win32k.sys base address");
                return 0;
            }


            KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);
            IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)win32k_base;
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
                KeUnstackDetachProcess(&apc);
                project_log_error("Invalid DOS headers");
                return 0;
            }

            IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)((uintptr_t)win32k_base + dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
                KeUnstackDetachProcess(&apc);
                project_log_error("Invalid NT headers");
                return 0;
            }

            IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uintptr_t)nt_headers + sizeof(IMAGE_NT_HEADERS64));
            const char* gadget_pattern = {
                "\x90\xE9"  // jmp near relative (32-bit offset is ommitted for pattern scanning)
            };

            uint32_t found_gadgets = 0;
            for (uint32_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
                // Limit yourself to only executable non-discardable sections
                if (!(sections[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                    !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                    (sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
                    continue;

                if (strncmp((const char*)sections[i].Name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
                    uintptr_t section_start = (uintptr_t)win32k_base + sections[i].VirtualAddress;
                    uint32_t section_size = sections[i].Misc.VirtualSize;

                    for (uint32_t curr_section_offset = 0; curr_section_offset < section_size; curr_section_offset++) {
                        uintptr_t result = utility::find_pattern_in_range((uintptr_t)section_start + curr_section_offset, section_size - curr_section_offset, gadget_pattern, 2, 0);
                        if (!result)
                            break;

                        // Parse the 32-bit relative offset
                        int32_t relative_offset = *(int32_t*)(result + 2);
                        uintptr_t next_instruction = result + 6;  // 1 byte for the nop and 5 bytes for the jmp (1 for opcode + 4 for offset)
                        uintptr_t jump_destination = next_instruction + relative_offset;

                        // Only use invalid addresses that we can later map
                        if (!MmIsAddressValid((void*)jump_destination)) {
                            found_gadgets++;
                        }

                        // Mov to after the end of our gadget
                        curr_section_offset = (uint32_t)(next_instruction - section_start);
                    }
                }
            }

            gadget_count = found_gadgets;
            gadget_info_t* gadget_addresses = (gadget_info_t*)ExAllocatePool(NonPagedPool, found_gadgets * sizeof(gadget_info_t));
            if (!gadget_addresses) {
                KeUnstackDetachProcess(&apc);
                project_log_error("Failed to alloc mem");
                return 0;
            }

            for (uint32_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
                // Limit yourself to only executable non-discardable sections
                if (!(sections[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                    !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                    (sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
                    continue;

                if (strncmp((const char*)sections[i].Name, ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
                    uintptr_t section_start = (uintptr_t)win32k_base + sections[i].VirtualAddress;
                    uint32_t section_size = sections[i].Misc.VirtualSize;

                    for (uint32_t curr_section_offset = 0; curr_section_offset < section_size; curr_section_offset++) {
                        uintptr_t result = utility::find_pattern_in_range((uintptr_t)section_start + curr_section_offset, section_size - curr_section_offset, gadget_pattern, 2, 0);
                        if (!result)
                            break;

                        // Parse the 32-bit relative offset
                        int32_t relative_offset = *(int32_t*)(result + 2);
                        uintptr_t next_instruction = result + 6;  // 1 byte for the nop and 5 bytes for the jmp (1 for opcode + 4 for offset)
                        uintptr_t jump_destination = next_instruction + relative_offset;

                        // Only use invalid addresses
                        if (!MmIsAddressValid((void*)jump_destination)) {
                            uint32_t curr_idx = found_gadgets - 1;
                            found_gadgets--;
   
                            gadget_addresses[curr_idx].gadget = (void*)result;
                            gadget_addresses[curr_idx].jump_destination = (void*)jump_destination;
                            if (found_gadgets == 0) {
                                KeUnstackDetachProcess(&apc);
                                return gadget_addresses;
                            }
                        }

                        // Mov to after the end of our gadget
                        curr_section_offset = (uint32_t)(result + 5 - section_start);
                    }
                }
            }

            KeUnstackDetachProcess(&apc);
            return 0;
        }

        project_status win_map_memory_page(void* memory) {
            project_status status = status_success;
            PHYSICAL_ADDRESS max_addr = { 0 };
            max_addr.QuadPart = MAXULONG64;

            va_64_t mem_va;
            mem_va.flags = (uint64_t)memory;

            pml4e_64* pml4_table = 0;
            pdpte_64* pdpt_table = 0;
            pde_64* pde_table = 0;
            pte_64* pte_table = 0;

            pml4_table = (pml4e_64*)win_get_virtual_address(__readcr3());
            if (!pml4_table)
                return status_win_address_translation_failed;

            pdpt_table = (pdpte_64*)win_get_virtual_address(pml4_table[mem_va.pml4e_idx].page_frame_number << 12);
            if (!pdpt_table) {
                /*
                    Follow the principle of bottom to top (Pte->Pde->Pdpte->Pml4) when populating to avoid race conditions / logical errors
                */
                void* allocated_mem = MmAllocateContiguousMemory(0x1000, max_addr);
                if (!allocated_mem)
                    return status_memory_allocation_failed;

                memset(allocated_mem, 0, 0x1000);

                uint64_t mem_pfn = win_get_physical_address(allocated_mem) >> 12;
                if (!mem_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_win_address_translation_failed;
                }

                pte_table = (pte_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pte_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_memory_allocation_failed;
                }
                memset(pte_table, 0, 0x1000);

                uint64_t pte_pfn = win_get_physical_address(pte_table) >> 12;
                if (!pte_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_win_address_translation_failed;
                }

                pde_table = (pde_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pde_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_memory_allocation_failed;
                }
                memset(pte_table, 0, 0x1000);

                uint64_t pde_pfn = win_get_physical_address(pde_table) >> 12;
                if (!pde_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    MmFreeContiguousMemory(pde_table);
                    return status_win_address_translation_failed;
                }

                pdpt_table = (pdpte_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pdpt_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    MmFreeContiguousMemory(pde_table);
                    return status_memory_allocation_failed;
                }
                memset(pte_table, 0, 0x1000);

                uint64_t pdpte_pfn = win_get_physical_address(pdpt_table) >> 12;
                if (!pdpte_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    MmFreeContiguousMemory(pde_table);
                    MmFreeContiguousMemory(pdpt_table);
                    return status_win_address_translation_failed;
                }

                pte_table[mem_va.pte_idx].flags = 0;
                pte_table[mem_va.pte_idx].present = 1;
                pte_table[mem_va.pte_idx].write = 1;
                pte_table[mem_va.pte_idx].global = 1;
                pte_table[mem_va.pte_idx].execute_disable = 0;
                pte_table[mem_va.pte_idx].page_frame_number = mem_pfn;

                pde_table[mem_va.pde_idx].flags = 0;
                pde_table[mem_va.pde_idx].present = 1;
                pde_table[mem_va.pde_idx].write = 1;
                pde_table[mem_va.pde_idx].execute_disable = 0;
                pde_table[mem_va.pde_idx].page_frame_number = pte_pfn;

                pdpt_table[mem_va.pdpte_idx].flags = 0;
                pdpt_table[mem_va.pdpte_idx].present = 1;
                pdpt_table[mem_va.pdpte_idx].write = 1;
                pdpt_table[mem_va.pdpte_idx].execute_disable = 0;
                pdpt_table[mem_va.pdpte_idx].page_frame_number = pde_pfn;

                pml4_table[mem_va.pml4e_idx].flags = 0;
                pml4_table[mem_va.pml4e_idx].present = 1;
                pml4_table[mem_va.pml4e_idx].write = 1;
                pml4_table[mem_va.pml4e_idx].execute_disable = 0;
                pml4_table[mem_va.pml4e_idx].page_frame_number = pdpte_pfn;

                __invlpg(memory);

                return status;
            }

            pde_table = (pde_64*)win_get_virtual_address(pdpt_table[mem_va.pdpte_idx].page_frame_number << 12);
            if (!pde_table) {
                /*
                    Follow the principle of bottom to top (Pte->Pde->Pdpte->Pml4) when populating to avoid race conditions / logical errors
                */
                void* allocated_mem = MmAllocateContiguousMemory(0x1000, max_addr);
                if (!allocated_mem)
                    return status_memory_allocation_failed;

                memset(allocated_mem, 0, 0x1000);

                uint64_t mem_pfn = win_get_physical_address(allocated_mem) >> 12;
                if (!mem_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_win_address_translation_failed;
                }

                pte_table = (pte_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pte_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_memory_allocation_failed;
                }
                memset(pte_table, 0, 0x1000);

                uint64_t pte_pfn = win_get_physical_address(pte_table) >> 12;
                if (!pte_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_win_address_translation_failed;
                }

                pde_table = (pde_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pde_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_memory_allocation_failed;
                }
                memset(pte_table, 0, 0x1000);

                uint64_t pde_pfn = win_get_physical_address(pde_table) >> 12;
                if (!pde_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    MmFreeContiguousMemory(pde_table);
                    return status_win_address_translation_failed;
                }

                pte_table[mem_va.pte_idx].flags = 0;
                pte_table[mem_va.pte_idx].present = 1;
                pte_table[mem_va.pte_idx].write = 1;
                pte_table[mem_va.pte_idx].global = 1;
                pte_table[mem_va.pte_idx].execute_disable = 0;
                pte_table[mem_va.pte_idx].page_frame_number = mem_pfn;

                pde_table[mem_va.pde_idx].flags = 0;
                pde_table[mem_va.pde_idx].present = 1;
                pde_table[mem_va.pde_idx].write = 1;
                pde_table[mem_va.pde_idx].execute_disable = 0;
                pde_table[mem_va.pde_idx].page_frame_number = pte_pfn;

                pdpt_table[mem_va.pdpte_idx].flags = 0;
                pdpt_table[mem_va.pdpte_idx].present = 1;
                pdpt_table[mem_va.pdpte_idx].write = 1;
                pdpt_table[mem_va.pdpte_idx].execute_disable = 0;
                pdpt_table[mem_va.pdpte_idx].page_frame_number = pde_pfn;

                __invlpg(memory);

                return status;
            }

            pte_table = (pte_64*)win_get_virtual_address(pde_table[mem_va.pde_idx].page_frame_number << 12);
            if (!pte_table) {
                /*
                    Follow the principle of bottom to top (Pte->Pde->Pdpte->Pml4) when populating to avoid race conditions / logical errors
                */
                void* allocated_mem = MmAllocateContiguousMemory(0x1000, max_addr);
                if (!allocated_mem)
                    return status_memory_allocation_failed;

                memset(allocated_mem, 0, 0x1000);

                uint64_t mem_pfn = win_get_physical_address(allocated_mem) >> 12;
                if (!mem_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_win_address_translation_failed;
                }

                pte_table = (pte_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pte_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_memory_allocation_failed;
                }
                memset(pte_table, 0, 0x1000);

                uint64_t pte_pfn = win_get_physical_address(pte_table) >> 12;
                if (!pte_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_win_address_translation_failed;
                }

                pte_table[mem_va.pte_idx].flags = 0;
                pte_table[mem_va.pte_idx].present = 1;
                pte_table[mem_va.pte_idx].write = 1;
                pte_table[mem_va.pte_idx].global = 1;
                pte_table[mem_va.pte_idx].execute_disable = 0;
                pte_table[mem_va.pte_idx].page_frame_number = mem_pfn;

                pde_table[mem_va.pde_idx].flags = 0;
                pde_table[mem_va.pde_idx].present = 1;
                pde_table[mem_va.pde_idx].write = 1;
                pde_table[mem_va.pde_idx].execute_disable = 0;
                pde_table[mem_va.pde_idx].page_frame_number = pte_pfn;

                __invlpg(memory);

                return status;
            }

            void* allocated_mem = MmAllocateContiguousMemory(0x1000, max_addr);
            if (!allocated_mem)
                return status_memory_allocation_failed;

            memset(allocated_mem, 0, 0x1000);

            uint64_t mem_pfn = win_get_physical_address(allocated_mem) >> 12;
            if (!mem_pfn) {
                MmFreeContiguousMemory(allocated_mem);
                return status_win_address_translation_failed;
            }

            pte_table[mem_va.pte_idx].flags = 0;
            pte_table[mem_va.pte_idx].present = 1;
            pte_table[mem_va.pte_idx].write = 1;
            pte_table[mem_va.pte_idx].global = 1;
            pte_table[mem_va.pte_idx].execute_disable = 0;
            pte_table[mem_va.pte_idx].page_frame_number = mem_pfn;

            __invlpg(memory);

            return status;
        }

        // Expects its parameters to be valid and mapped memory...
        void generate_jmp_shellcode(void* validated_jump_destination, void* shown_shellcode) {
            if (!validated_jump_destination || !shown_shellcode)
                return;

            static const uint8_t jump_shown_shellcode[] = {
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of handler_address)
                0xFF, 0xE0,                                                 // jmp rax
             };

            *(void**)((uint8_t*)jump_shown_shellcode + 2) = shown_shellcode;

            memcpy(validated_jump_destination, jump_shown_shellcode, sizeof(jump_shown_shellcode));
        }

        void log_gadget_info(uint32_t gadget_count, uint32_t random_index, gadget_info_t& selected_gadget) {
            project_log_info("Found %d gadgets", gadget_count);
            project_log_info("[%d] Selected gadget at %p points to %p", random_index, selected_gadget.gadget, selected_gadget.jump_destination);
        }

        project_status init_gadgets(void* shown_shellcode) {
            uint32_t gadget_count = 0;
            gadget_info_t* gadgets = find_possible_gadgets(gadget_count);
            if (!gadgets || !gadget_count) {
                project_log_error("Failed to find gadgets in win32kfull.sys %p %d", gadgets, gadget_count);
                return status_no_gadget_found;
            }

            uint32_t random_index = simple_random() % gadget_count;
            gadget_info_t& selected_gadget = gadgets[random_index];

            log_gadget_info(gadget_count, random_index, selected_gadget);

            // Now we have to map the memory this points to in windows' cr3
            project_status status = win_map_memory_page(selected_gadget.jump_destination);
            if (status != status_success) {
                project_log_error("Failed to map the gadget jump destination");
                ExFreePool(gadgets);
                return status;
            }

            generate_jmp_shellcode(selected_gadget.jump_destination, shown_shellcode);

            g_used_gadget = selected_gadget.gadget;
            g_used_gadget_jump_destination = selected_gadget.jump_destination;

            ExFreePool(gadgets);
            return status_success;
        }
    };

    project_status is_already_hooked(void** data_ptr_address, PEPROCESS winlogon_eproc) {
        KAPC_STATE apc = { 0 };
        project_status status;

        KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);
        // First check if it points to a valid region
        status = utility::is_data_ptr_in_valid_region((uint64_t)*data_ptr_address);
        if (status != status_success) {
            KeUnstackDetachProcess(&apc);
            project_log_error("[INVALID MODULE] Data ptr at: %p already hooked", data_ptr_address);
            return status;
        }

        // Then check whether the pattern it points to matches our pattern (indicating it already being hooked)
        uint8_t* target_bytes = (uint8_t*)*data_ptr_address;
        if (target_bytes[0] == 0x90 &&
            target_bytes[1] == 0xE9) {
            KeUnstackDetachProcess(&apc);
            project_log_error("[VALID MODULE] Data ptr at: %p already hooked", data_ptr_address);
            return status_data_ptr_invalid;
        }

        KeUnstackDetachProcess(&apc);

        return status_success;
    }

    project_status init_data_ptr_data(void) {
        project_status status = status_success;
        void* win32k_base = 0;
        PEPROCESS winlogon_eproc = 0;
        KAPC_STATE apc = { 0 };

        const char* patterns[3] = { "\x48\x83\xEC\x28\x48\x8B\x05\x99\x02", "\x48\x83\xEC\x28\x48\x8B\x05\x59\x02", "\x48\x83\xEC\x28\x48\x8B\x05\xF5\x9C" };
        uint64_t function = 0;

        int* displacement_ptr = 0;
        uint64_t target_address = 0;
        uint64_t orig_data_ptr = 0;

        status = utility::get_driver_module_base(L"win32k.sys", win32k_base);
        if (status != status_success) {
            project_log_error("Failed to get win32k.sys base address");
            goto cleanup;
        }

        status = utility::get_eprocess("winlogon.exe", winlogon_eproc);
        if (status != status_success) {
            project_log_error("Failed to get winlogon.exe eproc");
            goto cleanup;
        }

        KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

        // NtUserGetCPD
        // 48 83 EC 28 48 8B 05 99/59 02
        for (const auto& pattern : patterns) {
            function = utility::search_pattern_in_section(win32k_base, ".text", pattern, 9, 0x0);
            if (function)
                break;
        }

        if (!function) {
            status = status_failure;
            KeUnstackDetachProcess(&apc);
            project_log_error("Failed to find NtUserGetCPD; You are maybe running the wrong winver");
            goto cleanup;
        }

        displacement_ptr = (int*)(function + 7);
        target_address = function + 7 + 4 + *displacement_ptr;
        if (!target_address) {
            KeUnstackDetachProcess(&apc);
            project_log_error("Failed to find data ptr address");
            status = status_failure;
            goto cleanup;
        }

        orig_data_ptr = *(uint64_t*)target_address;
        KeUnstackDetachProcess(&apc);

        status = is_already_hooked((void**)target_address, winlogon_eproc);
        if (status != status_success)
            return status;

        g_data_ptr_address = (void**)target_address;
        g_orig_data_ptr_value = (void*)orig_data_ptr;

    cleanup:

        return status;
    }

    project_status init_cr3_mappings(void* driver_base, uint64_t driver_size) {

        // Ensure the driver is mapped in our cr3 even after removed from system page tables
        project_status status = physmem::remapping::ensure_memory_mapping_for_range(driver_base, driver_size, utility::get_cr3(4));
        if (status != status_success)
            return status;

        // Partially hide the shellcode
        status = physmem::remapping::overwrite_virtual_address_mapping(enter_constructed_space_shown, enter_constructed_space_executed,
            physmem::util::get_system_cr3().flags, physmem::util::get_system_cr3().flags);
        if (status != status_success)
            return status;

        return status;
    }

    project_status init_data_ptr_hook(void** data_ptr_address, void* new_data_ptr_value) {
        if (!data_ptr_address || !new_data_ptr_value)
            return status_invalid_parameter;

        project_status status = status_success;
        PEPROCESS winlogon_eproc = 0;
        KAPC_STATE apc = { 0 };

        status = utility::get_eprocess("winlogon.exe", winlogon_eproc);
        if (status != status_success) {
            project_log_error("Failed to get winlogon.exe EPROCESS");
            return status;
        }

        KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

        if (!InterlockedExchangePointer((void**)data_ptr_address, (void*)new_data_ptr_value)) {
            KeUnstackDetachProcess(&apc);
            project_log_error("Failed to exchange ptr at: %p", data_ptr_address);
            status = status_failure;
            return status;
        }

        KeUnstackDetachProcess(&apc);
        return status;
    }

    void log_shellcode_ptrs(void) {
        project_log_info("Shown entering shellcode at %p", enter_constructed_space_shown);
        project_log_info("Executed entering shellcode at %p", enter_constructed_space_executed);
        project_log_info("Exiting shellcode at %p", exit_constructed_space);
        project_log_info("Nmi shellcode at %p", nmi_shellcode);
    }


    project_status init_communication(void* driver_base, uint64_t driver_size) {
        project_status status = status_success;

        status = init_data_ptr_data();
        if (status != status_success)
            return status;

        status = shellcode::construct_shellcodes(enter_constructed_space_executed, enter_constructed_space_shown,
            exit_constructed_space, nmi_shellcode,
            interrupts::get_constructed_idt_ptr(), g_orig_data_ptr_value,
            asm_handler, physmem::util::get_constructed_cr3().flags);
        if (status != status_success)
            return status;

        status = init_cr3_mappings(driver_base, driver_size);
        if (status != status_success)
            return status;

        status = gadgets::init_gadgets(enter_constructed_space_shown);
        if (status != status_success)
            return status;

        status = init_data_ptr_hook(g_data_ptr_address, g_used_gadget);
        if (status != status_success)
            return status;

        return status;
    }

    project_status unhook_data_ptr(void) {
        if (!g_data_ptr_address || !g_orig_data_ptr_value)
            return status_failure;

        // Basically revert the data ptr swap
        project_status status = physmem::runtime::copy_memory_from_constructed_cr3(g_data_ptr_address, &g_orig_data_ptr_value, 
            sizeof(void*), shellcode::get_current_user_cr3());
        if (status != status_success)
            return status;

        // Unmap our gadget in order to not run out of gadgets to use when reloading the driver
        status = physmem::paging_manipulation::win_unmap_memory_range(g_used_gadget_jump_destination, shellcode::get_current_user_cr3(), 0x1000);
        if (status != status_success)
            return status;

        return status;
    }
};