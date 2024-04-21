#pragma once
#include "../includes/includes.hpp"

#include "physmem_structs.hpp"

// Undefine if you want to disable them
#define ENABLE_OUTPUT

// #define ENABLE_PHYSMEM_LOGGING
// #define ENABLE_PHYSMEM_TESTS
// #define ENABLE_EXPERIMENT_LOGGING
// #define ENABLE_EXPERIMENT_TESTS
// #define ENTRY_LOGGING
#define ENABLE_GENERAL_LOGGING

// Define a simple debug macro
#ifdef ENABLE_OUTPUT
#define dbg_log(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ##__VA_ARGS__)
#else
#define dbg_log(fmt, ...) (void)0
#endif

#ifdef ENABLE_GENERAL_LOGGING
#define dbg_log_main(fmt, ...) dbg_log("[MAIN] " fmt, ##__VA_ARGS__)
#else
#define dbg_log_main(fmt, ...) (void)0
#endif

#ifdef ENTRY_LOGGING
#define dbg_log_entry(fmt, ...) dbg_log("[ENTRY] " fmt, ##__VA_ARGS__)
#else
#define dbg_log_entry(fmt, ...) (void)0
#endif
inline uint64_t my_driver_base;
inline uint64_t my_driver_size;

bool physmem_experiment(void);

// Function to retrieve the physical address of a virtual address
inline uint64_t get_physical_address(void* virtual_address) {
    return MmGetPhysicalAddress(virtual_address).QuadPart;
}

// Function to retrieve the virtual address of a physical address
inline uint64_t get_virtual_address(uint64_t physical_address) {
    PHYSICAL_ADDRESS phys_addr = { 0 };
    phys_addr.QuadPart = physical_address;

    return (uint64_t)(MmGetVirtualForPhysical(phys_addr));
}

using func_sig = int(*)();

class physmem {
private:
    // Don't touch, low level shit
    page_table_t* page_tables;
    uint64_t free_pml4_index;
    paging_structs::cr3 my_cr3;
    paging_structs::cr3 global_kernel_cr3;

    // The bottom half will be erased if they are true,
    // and if they are false the top half will be erased
    bool erase_1gb_bot;
    bool erase_2mb_bot;
    bool erase_pte_bot;

    static physmem* physmem_instance;
    bool inited;

public:

    // Memory copying util
    uint64_t copy_memory_to_inside(paging_structs::cr3 source_cr3, uint64_t source, uint64_t destination, uint64_t size);
    uint64_t copy_memory_from_inside(uint64_t source, uint64_t destination, paging_structs::cr3 destination_cr3, uint64_t size);
    uint64_t copy_virtual_memory(paging_structs::cr3 source_cr3, uint64_t source, paging_structs::cr3 destination_cr3, uint64_t destination, uint64_t size);
    uint64_t copy_physical_memory(uint64_t source_physaddr, uint64_t destination_physaddr, uint64_t size);


    // These are not recommended to be called, since they are the most low level API you are gonna get
    uint64_t map_outside_virtual_addr(uint64_t outside_va, paging_structs::cr3 outside_cr3, uint64_t* offset_to_next_page);
    uint64_t map_outside_physical_addr(uint64_t outside_pa, uint64_t* offset_to_next_page);
    uint64_t get_outside_physical_addr(uint64_t outside_va, paging_structs::cr3 outside_cr3);

    // Helpers
    void free_pdpte_1gb_entries_half(paging_structs::pdpte_1gb_64* pdpte_1gb_table);
    void free_pde_2mb_entries_half(paging_structs::pde_2mb_64* pde_2mb_table);
    void free_pte_entries_half(paging_structs::pte_64* pte_table);

    // Checks whether a paging entry index is valid
    bool is_index_valid(uint64_t index) {
        bool valid = index <= 511;

        /*
        if (valid) {
            dbg_log("[VALID] Index: %d", index);
        } else {
            dbg_log("[INVALID] Index: %d", index);
        }
        */

        return valid;
    }

    // Paging structure manipulating utility
    paging_structs::pte_64 get_pte_entry(uint64_t outside_va, paging_structs::cr3 outside_cr3);
    bool set_pte_entry(uint64_t outside_va, paging_structs::cr3 outside_cr3, paging_structs::pte_64 new_ptr);
    bool set_address_range_not_global(uint64_t base, uint64_t size, paging_structs::cr3 outside_cr3);

    // Main function that is used and exposed
    static physmem* get_physmem_instance(void);

    // Setup and testing
    bool setup_paging_hierachy(void);
    bool test_page_tables(void);

    page_table_t* get_page_tables(void) {
        return page_tables;
    }

    bool is_inited(void) {
        return physmem_instance->inited;
    }

    // Returns the kernel cr3
    paging_structs::cr3 get_kernel_cr3(void) {
        // If it is not yet populated, we are also no yet inited, so we can just read the kernel cr3 
        // from cr3 because we are executing in a kernel context
        if (!global_kernel_cr3.flags)
            global_kernel_cr3.flags = __readcr3();

        return global_kernel_cr3;
    }

    paging_structs::cr3 get_my_cr3() {
        return my_cr3;
    }

};