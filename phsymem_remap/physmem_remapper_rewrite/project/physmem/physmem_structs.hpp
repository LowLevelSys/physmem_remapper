#pragma once
#include "../project_includes.hpp"

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
        uint64_t reserved1 : 1;
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

typedef union {

    struct {
        uint64_t offset_1gb : 30;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    struct {
        uint64_t offset_2mb : 21;
        uint64_t pde_idx : 9;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    struct {
        uint64_t offset_4kb : 12;
        uint64_t pte_idx : 9;
        uint64_t pde_idx : 9;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    uint64_t flags;
} va_64_t;

#define PAGE_TABLE_ENTRY_COUNT 512
struct page_tables_t {
    alignas(0x1000) pml4e_64 pml4_table[PAGE_TABLE_ENTRY_COUNT]; // Basically only is a windows copy; We replace one entry and point it to our paging structure
    alignas(0x1000) pdpte_64 pdpt_table[PAGE_TABLE_ENTRY_COUNT];
    alignas(0x1000) pde_2mb_64 pd_2mb_table[PAGE_TABLE_ENTRY_COUNT][PAGE_TABLE_ENTRY_COUNT];
};

#define REMAPPING_TABLE_COUNT 5
struct remapping_tables_t {
    union {
        pdpte_64* pdpt_table[REMAPPING_TABLE_COUNT];
        pdpte_1gb_64* pdpt_1gb_table[REMAPPING_TABLE_COUNT];
    };
    union {
        pde_64* pd_table[REMAPPING_TABLE_COUNT];
        pde_2mb_64* pd_2mb_table[REMAPPING_TABLE_COUNT];
    };

    pte_64* pt_table[REMAPPING_TABLE_COUNT];

    bool is_pdpt_table_occupied[REMAPPING_TABLE_COUNT];
    bool is_pd_table_occupied[REMAPPING_TABLE_COUNT];
    bool is_pt_table_occupied[REMAPPING_TABLE_COUNT];
};

struct physmem_t {
    // These page tables make up our cr3
    page_tables_t page_tables;

    // These page tables are sole entries we use to
    // remap addresses in our cr3
    remapping_tables_t remapping_tables;

    cr3 kernel_cr3;

    cr3 constructed_cr3;
    uint64_t mapped_physical_mem_base; // Is the base where we mapped the first 512 gb of physical memory 

    bool initialized;
};