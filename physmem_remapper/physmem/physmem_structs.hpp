#pragma once
#pragma warning(disable: 4201)
#include "../includes/includes.hpp"

namespace paging_structs {

    typedef union {
        struct {
            uint64_t protection_enable : 1;
            uint64_t monitor_coprocessor : 1;
            uint64_t emulate_fpu : 1;
            uint64_t task_switched : 1;
            uint64_t extension_type : 1;
            uint64_t numeric_error : 1;
            uint64_t reserved1 : 10;
            uint64_t write_protect : 1;
            uint64_t reserved2 : 1;
            uint64_t alignment_mask : 1;
            uint64_t reserved3 : 10;
            uint64_t not_write_through : 1;
            uint64_t cache_disable : 1;
            uint64_t paging_enable : 1;
            uint64_t reserved4 : 32;
        };

        uint64_t flags;
    } cr0;

    typedef union {
        struct {
            uint64_t reserved1 : 3;
            uint64_t page_level_write_through : 1;
            uint64_t page_level_cache_disable : 1;
            uint64_t reserved2 : 7;
            uint64_t address_of_page_directory : 36;
            uint64_t reserved3 : 16;
        };

        uint64_t flags;
    } cr3;
    typedef union
    {
        struct
        {
            uint64_t task_priority_level : 4;
            uint64_t reserved : 60;
        };

        uint64_t flags;
    } cr8;
    typedef union {
        struct {
            uint64_t virtual_mode_extensions : 1;
            uint64_t protected_mode_virtual_interrupts : 1;
            uint64_t timestamp_disable : 1;
            uint64_t debugging_extensions : 1;
            uint64_t page_size_extensions : 1;
            uint64_t physical_address_extension : 1;
            uint64_t machine_check_enable : 1;
            uint64_t page_global_enable : 1;
            uint64_t performance_monitoring_counter_enable : 1;
            uint64_t os_fxsave_fxrstor_support : 1;
            uint64_t os_xmm_exception_support : 1;
            uint64_t usermode_instruction_prevention : 1;
            uint64_t linear_addresses_57_bit : 1;
            uint64_t vmx_enable : 1;
            uint64_t smx_enable : 1;
            uint64_t fsgsbase_enable : 1;
            uint64_t pcid_enable : 1;
            uint64_t os_xsave : 1;
            uint64_t key_locker_enable : 1;
            uint64_t smep_enable : 1;
            uint64_t smap_enable : 1;
            uint64_t protection_key_enable : 1;
            uint64_t control_flow_enforcement_enable : 1;
            uint64_t protection_key_for_supervisor_mode_enable : 1;
            uint64_t reserved2 : 39;
        };

        uint64_t flags;
    } cr4;

    typedef union {
        struct {
            uint64_t present : 1;
            uint64_t write : 1;
            uint64_t supervisor : 1;
            uint64_t page_level_write_through : 1;
            uint64_t page_level_cache_disable : 1;
            uint64_t accessed : 1;
            uint64_t reserved1 : 1;
            uint64_t must_be_zero : 1;
            uint64_t ignored_1 : 4;
            uint64_t page_frame_number : 36;
            uint64_t reserved2 : 4;
            uint64_t ignored_2 : 11;
            uint64_t execute_disable : 1;
        };

        uint64_t flags;
    } pml4e_64;

    typedef union {
        struct {
            uint64_t present : 1;
            uint64_t write : 1;
            uint64_t supervisor : 1;
            uint64_t page_level_write_through : 1;
            uint64_t page_level_cache_disable : 1;
            uint64_t accessed : 1;
            uint64_t dirty : 1;
            uint64_t large_page : 1;
            uint64_t global : 1;
            uint64_t ignored_1 : 3;
            uint64_t pat : 1;
            uint64_t reserved1 : 17;
            uint64_t page_frame_number : 18;
            uint64_t reserved2 : 4;
            uint64_t ignored_2 : 7;
            uint64_t protection_key : 4;
            uint64_t execute_disable : 1;
        };

        uint64_t flags;
    } pdpte_1gb_64;

    typedef union {
        struct {
            uint64_t present : 1;
            uint64_t write : 1;
            uint64_t supervisor : 1;
            uint64_t page_level_write_through : 1;
            uint64_t page_level_cache_disable : 1;
            uint64_t accessed : 1;
            uint64_t reserved1 : 1;
            uint64_t large_page : 1;
            uint64_t ignored_1 : 4;
            uint64_t page_frame_number : 36;
            uint64_t reserved2 : 4;
            uint64_t ignored_2 : 11;
            uint64_t execute_disable : 1;
        };

        uint64_t flags;
    } pdpte_64;

    typedef union {
        struct {
            uint64_t present : 1;
            uint64_t write : 1;
            uint64_t supervisor : 1;
            uint64_t page_level_write_through : 1;
            uint64_t page_level_cache_disable : 1;
            uint64_t accessed : 1;
            uint64_t dirty : 1;
            uint64_t large_page : 1;
            uint64_t global : 1;
            uint64_t ignored_1 : 3;
            uint64_t pat : 1;
            uint64_t reserved1 : 8;
            uint64_t page_frame_number : 27;
            uint64_t reserved2 : 4;
            uint64_t ignored_2 : 7;
            uint64_t protection_key : 4;
            uint64_t execute_disable : 1;
        };

        uint64_t flags;
    } pde_2mb_64;

    typedef union {
        struct {
            uint64_t present : 1;
            uint64_t write : 1;
            uint64_t supervisor : 1;
            uint64_t page_level_write_through : 1;
            uint64_t page_level_cache_disable : 1;
            uint64_t accessed : 1;
            uint64_t reserved1 : 1;
            uint64_t large_page : 1;
            uint64_t ignored_1 : 4;
            uint64_t page_frame_number : 36;
            uint64_t reserved2 : 4;
            uint64_t ignored_2 : 11;
            uint64_t execute_disable : 1;
        };

        uint64_t flags;
    } pde_64;

    typedef union {
        struct {
            uint64_t present : 1;
            uint64_t write : 1;
            uint64_t supervisor : 1;
            uint64_t page_level_write_through : 1;
            uint64_t page_level_cache_disable : 1;
            uint64_t accessed : 1;
            uint64_t dirty : 1;
            uint64_t pat : 1;
            uint64_t global : 1;
            uint64_t ignored_1 : 3;
            uint64_t page_frame_number : 36;
            uint64_t reserved1 : 4;
            uint64_t ignored_2 : 7;
            uint64_t protection_key : 4;
            uint64_t execute_disable : 1;
        };

        uint64_t flags;
    } pte_64;
};

union virtual_address {
    uint64_t address;
    struct
    {
        uint64_t offset : 12;
        uint64_t pt_idx : 9;
        uint64_t pd_idx : 9;
        uint64_t pdpt_idx : 9;
        uint64_t pml4_idx : 9;
    };
};

#define MEMORY_COPYING_SLOT 0

#define NORMAL_PAGE_ENTRY 1 // Slot used for normal pages
#define LARGE_PAGE_ENTRY 0 // Slot used for large pages

#define TABLE_COUNT 100

#define MAX_REMAPPINGS 100

struct slot_t {
    uint32_t slot;
    bool large_page;
};

struct remapped_va_t {
    virtual_address remapped_va;

    // Pml4 slot not needed as we only have 1 anyways
    slot_t pdpte_slot;
    slot_t pde_slot;
    uint32_t pte_slot;
};

enum usable_until {
    pdpt_table_valid, // Means that the pml4 at the correct index already points to a remapped pdpt table
    pde_table_valid, // Means that the pdpt at the correct index already points to a remapped pde table
    pte_table_valid, // Means that the pde at the correct index already points to a remapped pte table
    non_valid, // Means that the pml4 indexes didn't match
};

#pragma optimize("", off)
struct page_table_t {
    // We copy the top layer of pml4's and insert a new entry for memory copying util
    __declspec(align(0x1000)) paging_structs::pml4e_64* pml4_table;

    // These are here for remapping
    union {
        __declspec(align(0x1000)) paging_structs::pdpte_64* pdpt_table[TABLE_COUNT];
        __declspec(align(0x1000)) paging_structs::pdpte_1gb_64* pdpt_1gb_table[TABLE_COUNT];
    };
    union {
        __declspec(align(0x1000)) paging_structs::pde_64* pde_table[TABLE_COUNT];
        __declspec(align(0x1000)) paging_structs::pde_2mb_64* pde_2mb_table[TABLE_COUNT];
    };

    __declspec(align(0x1000)) paging_structs::pte_64* pte_table[TABLE_COUNT];

    bool is_pdpt_table_occupied[TABLE_COUNT];

    bool is_pde_table_occupied[TABLE_COUNT];

    bool is_pte_table_occupied[TABLE_COUNT];

    remapped_va_t remapping_list[MAX_REMAPPINGS];
};
#pragma optimize("", on)