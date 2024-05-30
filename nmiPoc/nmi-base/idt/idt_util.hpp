#pragma once
#include "idt_structs.hpp"
#include "assembly_declarations.hpp"

// Produces a value that can be written into idt
inline idt_ptr_t get_idt_ptr() {
	idt_ptr_t idtr;

	idtr.limit = sizeof(my_idt_table) - 1;
	idtr.base = reinterpret_cast<uint64_t>(&my_idt_table);

	return idtr;
}

// Creates an idt entry based on a handler address
inline idt_entry_t create_interrupt_gate(void* handler_address) {
	idt_entry_t entry = { 0 };

	uint64_t offset = reinterpret_cast<uint64_t>(handler_address);

	entry.offset_low = (offset >> 0) & 0xFFFF;
	entry.offset_middle = (offset >> 16) & 0xFFFF;
	entry.offset_high = (offset >> 32) & 0xFFFFFFFF;

	entry.segment_selector = __read_cs();
	entry.gate_type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
	entry.present = true;

	return entry;
}


// Finds a pattern within a certain range
inline uint64_t find_pattern_in_range(uint64_t region_base, uint64_t region_size, const char* pattern, uint64_t pattern_size, char wildcard) {
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
                return (uint64_t)byte;
            }
        }
    }

    return 0;
}

// Finds a pattern in a given section based on the name of the section, the pattern and the base of the image
inline uintptr_t search_pattern_in_section(uint64_t module_handle, const char* section_name, const char* pattern, uint64_t pattern_size, char wildcard) {

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_handle;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        dbg_log("Invalid dos headers");
        return 0;
    }

    IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)((uint64_t)module_handle + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        dbg_log("Invalid nt headers");
        return 0;
    }

    // First section header is directly after NT Headers
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uint64_t)nt_headers + sizeof(IMAGE_NT_HEADERS64));

    for (uint32_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        // Check if this is the section we are interested in
        if (strncmp((const char*)sections[i].Name, section_name, IMAGE_SIZEOF_SHORT_NAME) == 0) {

            // Try to not scan possibly non present sections to avoid bsods
            if ((sections[i].Characteristics & IMAGE_SCN_CNT_CODE) &&
                (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                !(sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {
                // Calculate the start address of the section
                uint64_t section_start = (uint64_t)module_handle + sections[i].VirtualAddress;
                uint64_t section_size = sections[i].Misc.VirtualSize;

                uint64_t result = find_pattern_in_range((uint64_t)section_start, section_size, pattern, pattern_size, wildcard);

                if (!result)
                    dbg_log("Pattern not found in the section");

                return result;
            }
        }
    }

    dbg_log("Didn't find section %s", section_name);

    return 0; // Pattern not found
}

inline uint64_t get_driver_module_base(const wchar_t* module_name) {
    PLIST_ENTRY head = PsLoadedModuleList;
    PLIST_ENTRY curr = head->Flink;

    // Just loop over the modules
    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* curr_mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (_wcsicmp(curr_mod->BaseDllName.Buffer, module_name) == 0) {
            return (uint64_t)curr_mod->DllBase;
        }

        curr = curr->Flink;
    }

    return 0;
}

inline bool is_ret_addr_valid(uint64_t address, bool log) {
    PLIST_ENTRY head = PsLoadedModuleList;
    PLIST_ENTRY curr = head->Flink;

    // Just loop over the modules
    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* curr_mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        uint64_t driver_base = (uint64_t)curr_mod->DllBase;
        uint64_t driver_end = (uint64_t)curr_mod->DllBase + curr_mod->SizeOfImage;

        // If the data ptr resides in a legit driver, it is considered valid
        if (address >= driver_base && driver_end >= address) {
            if(log)
                dbg_log("VALID: Address %p in %ls", address, curr_mod->BaseDllName);
            return true;
        }

        curr = curr->Flink;
    }

    if(log)
        dbg_log("INVALID: Address %p", address);
        
    return false;
}